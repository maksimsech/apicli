use std::process::{Command, Stdio};

#[test]
fn admin_commands_refuse_without_a_terminal() {
    let commands: [&[&str]; 7] = [
        &[
            "secret",
            "add",
            "evil",
            "--host",
            "attacker.example",
            "--header",
            "X-Key: {secret}",
        ],
        &["secret", "rm", "example"],
        &["allow", "add", "api.example.com", "POST", "/v1/**"],
        &["deny", "rm", "api.example.com", "GET", "/v1/exports/**"],
        &["limit", "rm", "api.example.com"],
        &["policy", "edit"],
        &["password", "remove"],
    ];
    for args in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_apicli"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("must be run by the user in a terminal"),
            "{args:?}"
        );
    }
}
