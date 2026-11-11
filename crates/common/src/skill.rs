use std::{fs, path::PathBuf};

use directories::BaseDirs;

use crate::{Agent, Failure, SkillCommand};

pub fn skill(name: &str, content: &str, command: SkillCommand) -> Result<u8, Failure> {
    match command {
        SkillCommand::Print => {
            print!("{content}");
            Ok(0)
        }
        SkillCommand::Install { agent, path } => install(name, content, agent, path),
    }
}

fn install(
    name: &str,
    content: &str,
    agent: Option<Agent>,
    path: Option<PathBuf>,
) -> Result<u8, Failure> {
    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| Failure::Usage("no home directory".into()))?;
    let dir = match (agent, path) {
        (Some(agent), _) => home.join(skills(agent)),
        (None, Some(path)) => match path.strip_prefix("~") {
            Ok(rest) => home.join(rest),
            Err(_) => path,
        },
        (None, None) => {
            return Err(Failure::Usage(
                "pass --agent claude|codex|opencode or --path DIR".into(),
            ));
        }
    };
    let dir = dir.join(name);
    let file = dir.join("SKILL.md");
    fs::create_dir_all(&dir)
        .and_then(|_| fs::write(&file, content))
        .map_err(|error| Failure::Write(format!("{}: {error}", file.display())))?;
    println!("Installed {}", file.display());
    Ok(0)
}

fn skills(agent: Agent) -> &'static str {
    match agent {
        Agent::Claude => ".claude/skills",
        Agent::Codex => ".agents/skills",
        Agent::Opencode => ".config/opencode/skills",
    }
}
