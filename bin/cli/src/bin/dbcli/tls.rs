use std::{io, sync::Arc};

use apicli::Failure;
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, lookup_host},
};
use tokio_rustls::{TlsConnector, client::TlsStream};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub async fn dial(host: &str, port: u16) -> Result<TcpStream, Failure> {
    let addresses = lookup_host((host, port))
        .await
        .map_err(|error| Failure::Dns(format!("{host}: {error}")))?;
    let mut last = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(Failure::Connect(match last {
        Some(error) => format!("{host}, port {port}: {error}"),
        None => format!("{host} has no addresses"),
    }))
}

pub async fn secure(
    host: &str,
    root_cert: Option<&str>,
    alpn: Option<&[u8]>,
    parameter: &str,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>, Failure> {
    let config = config(root_cert, alpn)?;
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| Failure::Tls(format!("{host} is not a valid TLS server name")))?;
    TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .map_err(|error| {
            Failure::Tls(format!(
                "{error}\nfor a private CA, the user can add {parameter}=PATH to the connection URL"
            ))
        })
}

pub fn lost(error: io::Error) -> Failure {
    Failure::Network(error.to_string())
}

fn config(root_cert: Option<&str>, alpn: Option<&[u8]>) -> Result<ClientConfig, Failure> {
    let failed = |error: rustls::Error| Failure::Tls(error.to_string());
    let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(failed)?;
    let mut config = match root_cert {
        None | Some("system") => builder
            .with_platform_verifier()
            .map_err(failed)?
            .with_no_client_auth(),
        Some(path) => {
            let unreadable = |error: rustls::pki_types::pem::Error| {
                Failure::Read(format!("the CA file {path}: {error}"))
            };
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(path).map_err(unreadable)? {
                roots.add(cert.map_err(unreadable)?).map_err(failed)?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Ok(config)
}
