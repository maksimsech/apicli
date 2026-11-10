#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(String),
    Quoted(String),
    Text(String),
    Symbol(char),
}

pub struct Lexed {
    pub token: Token,
    pub start: usize,
    pub end: usize,
}

pub struct Statement {
    pub text: String,
    pub line: usize,
    pub terminated: bool,
}

pub fn tokens(text: &str, backslash: bool) -> Vec<Lexed> {
    let chars = text.char_indices().collect::<Vec<_>>();
    let at = |index: usize| chars.get(index).map(|(_, character)| *character);
    let offset = |index: usize| chars.get(index).map_or(text.len(), |(offset, _)| *offset);
    let mut tokens = Vec::new();
    let mut index = 0;
    while let Some(character) = at(index) {
        let start = index;
        match (character, at(index + 1)) {
            (character, _) if character.is_whitespace() => {
                index += 1;
                continue;
            }
            ('-', Some('-')) | ('/', Some('/')) | ('#', _) => {
                while at(index).is_some_and(|character| character != '\n') {
                    index += 1;
                }
                continue;
            }
            ('/', Some('*')) => {
                index += 2;
                while at(index).is_some() && !(at(index) == Some('*') && at(index + 1) == Some('/'))
                {
                    index += 1;
                }
                index = (index + 2).min(chars.len());
                continue;
            }
            ('\'' | '"' | '`', _) => {
                let mut value = String::new();
                index += 1;
                while let Some(next) = at(index) {
                    index += 1;
                    if next == character {
                        if at(index) == Some(character) {
                            value.push(character);
                            index += 1;
                            continue;
                        }
                        break;
                    }
                    if next == '\\' && backslash {
                        if let Some(escaped) = at(index) {
                            value.push(escaped);
                            index += 1;
                        }
                        continue;
                    }
                    value.push(next);
                }
                let token = if character == '\'' {
                    Token::Text(value)
                } else {
                    Token::Quoted(value)
                };
                tokens.push(Lexed {
                    token,
                    start: offset(start),
                    end: offset(index),
                });
                continue;
            }
            ('$', _) => {
                let mut tag_end = index + 1;
                while at(tag_end)
                    .is_some_and(|character| character.is_alphanumeric() || character == '_')
                {
                    tag_end += 1;
                }
                if at(tag_end) == Some('$') {
                    let tag = chars[index..=tag_end]
                        .iter()
                        .map(|(_, character)| character)
                        .collect::<String>();
                    let body = offset(tag_end + 1);
                    let (value, end) = match text[body..].find(&tag) {
                        Some(found) => (
                            text[body..body + found].to_string(),
                            body + found + tag.len(),
                        ),
                        None => (text[body..].to_string(), text.len()),
                    };
                    tokens.push(Lexed {
                        token: Token::Text(value),
                        start: offset(start),
                        end,
                    });
                    index = chars.partition_point(|(offset, _)| *offset < end);
                    continue;
                }
                index += 1;
                tokens.push(Lexed {
                    token: Token::Symbol('$'),
                    start: offset(start),
                    end: offset(index),
                });
            }
            (character, _) if character.is_alphanumeric() || character == '_' => {
                while at(index)
                    .is_some_and(|character| character.is_alphanumeric() || character == '_')
                {
                    index += 1;
                }
                tokens.push(Lexed {
                    token: Token::Word(text[offset(start)..offset(index)].to_string()),
                    start: offset(start),
                    end: offset(index),
                });
            }
            (character, _) => {
                index += 1;
                tokens.push(Lexed {
                    token: Token::Symbol(character),
                    start: offset(start),
                    end: offset(index),
                });
            }
        }
    }
    tokens
}

pub fn split(text: &str, backslash: bool, batches: bool) -> Vec<Statement> {
    let tokens = tokens(text, backslash);
    let mut statements = Vec::new();
    let mut first: Option<usize> = None;
    let mut batch = false;
    for (index, lexed) in tokens.iter().enumerate() {
        if first.is_none() {
            if lexed.token == Token::Symbol(';') {
                continue;
            }
            first = Some(index);
            batch = batches && word(&lexed.token, "BEGIN");
        }
        if batch
            && word(&lexed.token, "BATCH")
            && index > 0
            && word(&tokens[index - 1].token, "APPLY")
        {
            batch = false;
        }
        if lexed.token == Token::Symbol(';')
            && !batch
            && let Some(start) = first.take()
        {
            statements.push(piece(text, &tokens[start..index], true));
        }
    }
    if let Some(start) = first {
        statements.push(piece(text, &tokens[start..], false));
    }
    statements
}

pub fn word(token: &Token, expected: &str) -> bool {
    matches!(token, Token::Word(word) if word.eq_ignore_ascii_case(expected))
}

fn piece(text: &str, tokens: &[Lexed], terminated: bool) -> Statement {
    let start = tokens.first().map_or(0, |lexed| lexed.start);
    let end = tokens.last().map_or(start, |lexed| lexed.end);
    Statement {
        text: text[start..end].to_string(),
        line: text[..start].matches('\n').count() + 1,
        terminated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(text: &str, backslash: bool) -> Vec<String> {
        split(text, backslash, true)
            .into_iter()
            .map(|statement| statement.text)
            .collect()
    }

    #[test]
    fn splits_only_on_top_level_semicolons() {
        assert_eq!(
            texts(
                "select 'a;b' from t; -- c;d\n/* e;f */ insert into t (\"x;y\") values ($$g;h$$);;",
                false
            ),
            [
                "select 'a;b' from t",
                "insert into t (\"x;y\") values ($$g;h$$)"
            ]
        );
        assert_eq!(
            texts(r"select 'a\';b' ; select `c;d`; select $tag$e;f$tag$", true),
            [r"select 'a\';b'", "select `c;d`", "select $tag$e;f$tag$"]
        );
        assert_eq!(texts(r"select 'a\'; delete from t", false).len(), 2);
    }

    #[test]
    fn keeps_a_batch_together() {
        assert_eq!(
            texts(
                "BEGIN BATCH INSERT INTO a (k) VALUES (1); DELETE FROM b WHERE k = 1; APPLY BATCH; TRUNCATE c",
                false
            ),
            [
                "BEGIN BATCH INSERT INTO a (k) VALUES (1); DELETE FROM b WHERE k = 1; APPLY BATCH",
                "TRUNCATE c"
            ]
        );
    }
}
