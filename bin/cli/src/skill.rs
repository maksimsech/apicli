use std::{fs, path::PathBuf};

use directories::BaseDirs;

use crate::{
    cli::{Agent, SkillCommand},
    failure::Failure,
};

const SKILL: &str = include_str!("../skill/SKILL.md");

pub fn skill(command: SkillCommand) -> Result<u8, Failure> {
    match command {
        SkillCommand::Print => {
            print!("{SKILL}");
            Ok(0)
        }
        SkillCommand::Install { agent, path } => install(agent, path),
    }
}

fn install(agent: Option<Agent>, path: Option<PathBuf>) -> Result<u8, Failure> {
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
    let dir = dir.join("apicli");
    let file = dir.join("SKILL.md");
    fs::create_dir_all(&dir)
        .and_then(|_| fs::write(&file, SKILL))
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
