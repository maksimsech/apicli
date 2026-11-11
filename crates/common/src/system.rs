use std::process::ExitCode;

use serde::Serialize;

use crate::Failure;

pub fn exit(tool: &str, result: Result<u8, Failure>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code),
        Err(Failure::Database(message)) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
        Err(failure) => {
            for line in failure.to_string().lines() {
                eprintln!("{tool}: {line}");
            }
            ExitCode::from(failure.code())
        }
    }
}

pub fn print_json(value: &impl Serialize) -> Result<(), Failure> {
    let text = serde_json::to_string(value).map_err(|error| Failure::Write(error.to_string()))?;
    println!("{text}");
    Ok(())
}

#[cfg(unix)]
pub fn disable_core_dumps() {
    use libc::{RLIMIT_CORE, rlimit, setrlimit};

    let limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        setrlimit(RLIMIT_CORE, &limit);
    }
}

#[cfg(not(unix))]
pub fn disable_core_dumps() {}
