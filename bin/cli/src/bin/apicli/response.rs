use std::{
    fs::File,
    io::{self, BufWriter, Write},
    time::Instant,
};

use apicli::{Entry, Failure};
use fieldkit_policy::Redactor;
use reqwest::{Method, Response, Version, header::CONTENT_TYPE};

use crate::{cli::RequestArgs, network::network};

pub async fn write(
    mut response: Response,
    args: &RequestArgs,
    method: &Method,
    started: Instant,
    mut redactor: Redactor,
    stdout: &mut dyn Write,
    entry: &mut Entry,
) -> Result<u8, Failure> {
    let status = response.status();
    entry.status = Some(status.as_u16());
    let failed = status.is_client_error() || status.is_server_error();
    let quiet = failed && args.fail && !args.fail_with_body;
    if args.verbose {
        print_head(&response, &redactor);
    }
    let head = redactor.redact(head(&response).as_bytes());
    let url = response.url().to_string();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default();
    let mut file = match &args.output {
        Some(path) if path.as_os_str() != "-" => {
            Some(BufWriter::new(File::create(path).map_err(|error| {
                Failure::Write(format!("{}: {error}", path.display()))
            })?))
        }
        _ => None,
    };
    let mut size = 0;
    {
        let out: &mut dyn Write = match &mut file {
            Some(file) => file,
            None => &mut *stdout,
        };
        if (args.include || args.head) && !quiet {
            out.write_all(&head).map_err(write_failure)?;
        }
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            size += chunk.len();
            if !quiet {
                out.write_all(&redactor.push(&chunk))
                    .map_err(write_failure)?;
            }
        }
        if !quiet {
            out.write_all(&redactor.finish()).map_err(write_failure)?;
        }
        out.flush().map_err(write_failure)?;
    }
    entry.bytes = Some(size);
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
        stdout
            .write_all(&redactor.redact(text.as_bytes()))
            .and_then(|_| stdout.flush())
            .map_err(write_failure)?;
    }
    if failed {
        eprintln!("apicli: HTTP {status}");
    }
    if failed && (args.fail || args.fail_with_body) {
        Ok(22)
    } else {
        Ok(0)
    }
}

pub fn print_head(response: &Response, redactor: &Redactor) {
    let head = redactor.redact(head(response).as_bytes());
    for line in String::from_utf8_lossy(&head).lines() {
        eprintln!("< {line}");
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

fn expand(template: &str, values: &[(&str, String)]) -> String {
    let template = template
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t");
    let mut text = String::new();
    let mut rest = template.as_str();
    while let Some(start) = rest.find("%{") {
        text.push_str(&rest[..start]);
        rest = &rest[start..];
        let found = rest.find('}').and_then(|end| {
            values
                .iter()
                .find(|(name, _)| *name == &rest[2..end])
                .map(|(_, value)| (end, value))
        });
        match found {
            Some((end, value)) => {
                text.push_str(value);
                rest = &rest[end + 1..];
            }
            None => {
                text.push_str("%{");
                rest = &rest[2..];
            }
        }
    }
    text.push_str(rest);
    text
}

fn write_failure(error: io::Error) -> Failure {
    Failure::Write(error.to_string())
}
