use unicode_width::UnicodeWidthStr;

const NUMERIC: [u32; 11] = [20, 21, 23, 26, 28, 29, 700, 701, 790, 1700, 5069];

pub struct Column {
    pub name: String,
    pub type_oid: u32,
}

pub struct Table {
    pub title: Option<String>,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Option<String>>>,
    pub footers: Vec<String>,
    pub count: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Aligned,
    Unaligned,
    Csv,
}

pub struct Options {
    pub format: Format,
    pub expanded: bool,
    pub tuples_only: bool,
    pub footer: bool,
    pub null: String,
    pub field_separator: String,
    pub quiet: bool,
}

impl Table {
    fn cells(&self, options: &Options) -> Vec<Vec<String>> {
        self.rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|cell| cell.clone().unwrap_or_else(|| options.null.clone()))
                    .collect()
            })
            .collect()
    }

    fn footers(&self, options: &Options) -> Vec<String> {
        if !self.footers.is_empty() {
            self.footers.clone()
        } else if self.count && options.footer {
            vec![match self.rows.len() {
                1 => "(1 row)".to_string(),
                count => format!("({count} rows)"),
            }]
        } else {
            Vec::new()
        }
    }
}

pub fn render(table: &Table, options: &Options) -> String {
    let cells = table.cells(options);
    match (options.format, options.expanded) {
        (Format::Aligned, false) => aligned(table, &cells, options),
        (Format::Aligned, true) => aligned_expanded(table, &cells, options),
        (Format::Unaligned, false) => unaligned(table, &cells, options),
        (Format::Unaligned, true) => unaligned_expanded(table, &cells, options),
        (Format::Csv, false) => csv(table, &cells, options),
        (Format::Csv, true) => csv_expanded(table, &cells),
    }
}

fn aligned(table: &Table, cells: &[Vec<String>], options: &Options) -> String {
    let count = table.columns.len();
    let lines = cells
        .iter()
        .map(|row| row.iter().map(|cell| split(cell)).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut widths = table
        .columns
        .iter()
        .map(|column| column.name.width())
        .collect::<Vec<_>>();
    for row in &lines {
        for (index, cell) in row.iter().enumerate() {
            for line in cell {
                widths[index] = widths[index].max(line.width());
            }
        }
    }
    let right = table
        .columns
        .iter()
        .map(|column| NUMERIC.contains(&column.type_oid))
        .collect::<Vec<_>>();
    let mut out = String::new();
    if !options.tuples_only {
        if let Some(title) = &table.title {
            let total = widths.iter().map(|width| width + 2).sum::<usize>() + count.max(1) - 1;
            out.push_str(&" ".repeat(total.saturating_sub(title.width()) / 2));
            out.push_str(title);
            out.push('\n');
        }
        let header = table
            .columns
            .iter()
            .zip(&widths)
            .map(|(column, width)| {
                let space = width - column.name.width();
                format!(
                    " {}{}{} ",
                    " ".repeat(space / 2),
                    column.name,
                    " ".repeat(space.div_ceil(2))
                )
            })
            .collect::<Vec<_>>();
        out.push_str(&header.join("|"));
        out.push('\n');
        let rule = widths
            .iter()
            .map(|width| "-".repeat(width + 2))
            .collect::<Vec<_>>();
        out.push_str(&rule.join("+"));
        out.push('\n');
    }
    for row in &lines {
        let height = row.iter().map(Vec::len).max().unwrap_or(1);
        for line in 0..height {
            for (index, cell) in row.iter().enumerate() {
                let last = index + 1 == count;
                out.push(' ');
                let more = cell.len() > line + 1;
                match cell.get(line) {
                    None if !last => out.push_str(&" ".repeat(widths[index])),
                    None => {}
                    Some(text) => {
                        let pad = " ".repeat(widths[index] - text.width());
                        if right[index] {
                            out.push_str(&pad);
                            out.push_str(text);
                        } else {
                            out.push_str(text);
                            if !last || more {
                                out.push_str(&pad);
                            }
                        }
                    }
                }
                if more {
                    out.push('+');
                } else if !last {
                    out.push(' ');
                }
                if !last {
                    out.push('|');
                }
            }
            out.push('\n');
        }
    }
    if !options.tuples_only {
        for footer in table.footers(options) {
            out.push_str(&footer);
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

fn aligned_expanded(table: &Table, cells: &[Vec<String>], options: &Options) -> String {
    let mut out = String::new();
    if !options.tuples_only
        && let Some(title) = &table.title
    {
        out.push_str(title);
        out.push('\n');
    }
    if cells.is_empty() {
        if !options.tuples_only {
            for footer in table.footers(options) {
                out.push_str(&footer);
                out.push('\n');
            }
        }
        out.push('\n');
        return out;
    }
    let names = table
        .columns
        .iter()
        .map(|column| column.name.width())
        .max()
        .unwrap_or(0);
    let values = cells
        .iter()
        .flatten()
        .flat_map(|cell| split(cell))
        .map(|line| line.width())
        .max()
        .unwrap_or(0);
    for (record, row) in cells.iter().enumerate() {
        if !options.tuples_only {
            let mut line = format!("-[ RECORD {} ]", record + 1);
            if line.len() <= names + 1 {
                line.push_str(&"-".repeat(names + 1 - line.len()));
                line.push('+');
            }
            let total = names + values + 3;
            if line.len() < total {
                line.push_str(&"-".repeat(total - line.len()));
            }
            out.push_str(&line);
            out.push('\n');
        } else if record > 0 {
            out.push_str(&format!(
                "{}+{}\n",
                "-".repeat(names + 1),
                "-".repeat(values + 1)
            ));
        }
        for (column, cell) in table.columns.iter().zip(row) {
            let lines = split(cell);
            for (index, text) in lines.iter().enumerate() {
                let name = if index == 0 { column.name.as_str() } else { "" };
                out.push_str(name);
                out.push_str(&" ".repeat(names - name.width()));
                out.push_str(" | ");
                out.push_str(text);
                if index + 1 < lines.len() {
                    out.push_str(&" ".repeat(values - text.width()));
                    out.push('+');
                }
                out.push('\n');
            }
        }
    }
    if !options.tuples_only {
        for footer in &table.footers {
            out.push_str(footer);
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

fn unaligned(table: &Table, cells: &[Vec<String>], options: &Options) -> String {
    let separator = options.field_separator.as_str();
    let mut out = String::new();
    if !options.tuples_only {
        if let Some(title) = &table.title {
            out.push_str(title);
            out.push('\n');
        }
        let names = table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>();
        out.push_str(&names.join(separator));
        out.push('\n');
    }
    for row in cells {
        out.push_str(&row.join(separator));
        out.push('\n');
    }
    if !options.tuples_only {
        for footer in table.footers(options) {
            out.push_str(&footer);
            out.push('\n');
        }
    }
    out
}

fn unaligned_expanded(table: &Table, cells: &[Vec<String>], options: &Options) -> String {
    let separator = options.field_separator.as_str();
    let mut out = String::new();
    if !options.tuples_only
        && let Some(title) = &table.title
    {
        out.push_str(title);
        out.push('\n');
    }
    if cells.is_empty() {
        if !options.tuples_only {
            for footer in table.footers(options) {
                out.push_str(&footer);
                out.push('\n');
            }
        }
        return out;
    }
    for (record, row) in cells.iter().enumerate() {
        if record > 0 {
            out.push('\n');
        }
        for (column, cell) in table.columns.iter().zip(row) {
            out.push_str(&format!("{}{separator}{cell}\n", column.name));
        }
    }
    if !options.tuples_only && !table.footers.is_empty() {
        out.push('\n');
        for footer in &table.footers {
            out.push_str(footer);
            out.push('\n');
        }
    }
    out
}

fn csv(table: &Table, cells: &[Vec<String>], options: &Options) -> String {
    let mut out = String::new();
    if !options.tuples_only {
        let names = table
            .columns
            .iter()
            .map(|column| quote(&column.name))
            .collect::<Vec<_>>();
        out.push_str(&names.join(","));
        out.push('\n');
    }
    for row in cells {
        let fields = row.iter().map(|cell| quote(cell)).collect::<Vec<_>>();
        out.push_str(&fields.join(","));
        out.push('\n');
    }
    out
}

fn csv_expanded(table: &Table, cells: &[Vec<String>]) -> String {
    let mut out = String::new();
    for row in cells {
        for (column, cell) in table.columns.iter().zip(row) {
            out.push_str(&format!("{},{}\n", quote(&column.name), quote(cell)));
        }
    }
    out
}

fn quote(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn split(cell: &str) -> Vec<String> {
    cell.split('\n').map(expand_tabs).collect()
}

fn expand_tabs(line: &str) -> String {
    let mut out = String::new();
    for character in line.chars() {
        if character == '\t' {
            let width = out.width();
            out.push_str(&" ".repeat(8 - width % 8));
        } else {
            out.push(character);
        }
    }
    out
}
