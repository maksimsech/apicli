use std::{
    fs::File,
    io::{self, BufWriter, Write, stdout},
    process::ExitCode,
    time::Instant,
};

use reqwest::{Method, Response, Version, header::CONTENT_TYPE};

use crate::{cli::RequestArgs, failure::Failure};

pub async fn write(
    mut response: Response,
    args: &RequestArgs,
    method: &Method,
    started: Instant,
) -> Result<ExitCode, Failure> {
    let status = response.status();
    let failed = status.is_client_error() || status.is_server_error();
    let quiet = failed && args.fail && !args.fail_with_body;
    let head = head(&response);
    if args.verbose {
        for line in head.lines() {
            eprintln!("< {line}");
        }
    }
    let url = response.url().to_string();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default();
    let mut out = output(args)?;
    if (args.include || args.head) && !quiet {
        out.write_all(head.as_bytes()).map_err(write_failure)?;
    }
    let mut size = 0;
    while let Some(chunk) = response.chunk().await? {
        size += chunk.len();
        if !quiet {
            out.write_all(&chunk).map_err(write_failure)?;
        }
    }
    out.flush().map_err(write_failure)?;
    drop(out);
    if let Some(template) = &args.write_out {
        let code = format!("{:03}", status.as_u16());
        let text = expand(
            template,
            &[
                ("http_code", code.clone()),
                ("response_code", code),
                (
                    "time_total",
                    format!("{:.6}", started.elapsed().as_secs_f64()),
                ),
                ("size_download", size.to_string()),
                ("content_type", content_type),
                ("url_effective", url),
                ("method", method.to_string()),
            ],
        );
        let mut stdout = stdout().lock();
        stdout
            .write_all(text.as_bytes())
            .and_then(|_| stdout.flush())
            .map_err(write_failure)?;
    }
    if failed {
        eprintln!("apicli: HTTP {status}");
    }
    if failed && (args.fail || args.fail_with_body) {
        Ok(ExitCode::from(22))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn head(response: &Response) -> String {
    let status = response.status();
    let mut text = match response.version() {
        Version::HTTP_2 => format!("HTTP/2 {}\r\n", status.as_u16()),
        Version::HTTP_3 => format!("HTTP/3 {}\r\n", status.as_u16()),
        version => format!("{version:?} {status}\r\n"),
    };
    for (name, value) in response.headers() {
        text.push_str(&format!(
            "{name}: {}\r\n",
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    text.push_str("\r\n");
    text
}

fn output(args: &RequestArgs) -> Result<Box<dyn Write>, Failure> {
    match &args.output {
        Some(path) if path.as_os_str() != "-" => {
            let file = File::create(path)
                .map_err(|error| Failure::Write(format!("{}: {error}", path.display())))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        _ => Ok(Box::new(BufWriter::new(stdout().lock()))),
    }
}

fn expand(template: &str, values: &[(&str, String)]) -> String {
    let mut text = template
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t");
    for (name, value) in values {
        text = text.replace(&format!("%{{{name}}}"), value);
    }
    text
}

fn write_failure(error: io::Error) -> Failure {
    Failure::Write(error.to_string())
}
