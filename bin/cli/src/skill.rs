use std::{fs, path::PathBuf};

use directories::BaseDirs;

use crate::{
    cli::{SkillCommand, Target},
    failure::Failure,
};

const SKILL: &str = include_str!("../skill/SKILL.md");
const TARGETS: [Target; 4] = [
    Target::Claude,
    Target::Opencode,
    Target::Codex,
    Target::Agents,
];

pub fn skill(command: SkillCommand) -> Result<u8, Failure> {
    match command {
        SkillCommand::Print => {
            print!("{SKILL}");
            Ok(0)
        }
        SkillCommand::Install { target, path } => install(target, path),
    }
}

fn install(target: Option<Target>, path: Option<PathBuf>) -> Result<u8, Failure> {
    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| Failure::Usage("no home directory".into()))?;
    let dirs = match (path, target) {
        (Some(path), _) => vec![path],
        (None, Some(target)) => vec![home.join(config(target)).join("skills")],
        (None, None) => TARGETS
            .iter()
            .filter(|target| home.join(config(**target)).is_dir())
            .map(|target| home.join(config(*target)).join("skills"))
            .collect(),
    };
    if dirs.is_empty() {
        return Err(Failure::Usage(
            "no agent tools found in ~/.claude, ~/.config/opencode, ~/.codex or ~/.agents. Use --target or --path".into(),
        ));
    }
    for dir in dirs {
        let dir = dir.join("apicli");
        let file = dir.join("SKILL.md");
        fs::create_dir_all(&dir)
            .and_then(|_| fs::write(&file, SKILL))
            .map_err(|error| Failure::Write(format!("{}: {error}", file.display())))?;
        println!("Installed {}", file.display());
    }
    Ok(0)
}

fn config(target: Target) -> &'static str {
    match target {
        Target::Claude => ".claude",
        Target::Opencode => ".config/opencode",
        Target::Codex => ".codex",
        Target::Agents => ".agents",
    }
}
