use std::time::Duration;

use apicli::Failure;
use apicli_policy::{Connection, Tls};
use bytes::{Buf, BytesMut};
use secrecy::ExposeSecret;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::reply::{Parser, Reply, lossy};
use crate::shared::{Io, dial, lost, rotate_hint, secure};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Client {
    io: Box<dyn Io>,
    buf: BytesMut,
}

impl Client {
    pub async fn open(connection: &Connection, db: u32) -> Result<Client, Failure> {
        timeout(CONNECT_TIMEOUT, Client::start(connection, db))
            .await
            .map_err(|_| Failure::Timeout)?
    }

    async fn start(connection: &Connection, db: u32) -> Result<Client, Failure> {
        let url = &connection.url;
        let stream = dial(&url.host, url.port).await?;
        let io: Box<dyn Io> = if url.tls == Tls::Require {
            Box::new(secure(&url.host, url.root_cert.as_deref(), None, "cacert", stream).await?)
        } else {
            Box::new(stream)
        };
        let mut client = Client {
            io,
            buf: BytesMut::with_capacity(8192),
        };
        let password = connection.password.expose_secret().as_bytes();
        let mut auth = vec![&b"AUTH"[..]];
        if !url.user.is_empty() {
            auth.push(url.user.as_bytes());
        }
        auth.push(password);
        if let Reply::Error(error) = client.call(&auth).await? {
            let error = lossy(&error);
            let mut text = format!("{}, port {}: AUTH failed: {error}", url.host, url.port);
            if error.starts_with("WRONGPASS") {
                text.push_str(&format!(
                    "
{}",
                    rotate_hint(&connection.name)
                ));
            }
            return Err(Failure::Connect(text));
        }
        if db != 0
            && let Reply::Error(error) =
                client.call(&[b"SELECT", db.to_string().as_bytes()]).await?
        {
            return Err(Failure::Database(lossy(&error)));
        }
        Ok(client)
    }

    pub async fn call(&mut self, args: &[&[u8]]) -> Result<Reply, Failure> {
        let mut out = format!("*{}\r\n", args.len()).into_bytes();
        for arg in args {
            out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            out.extend_from_slice(arg);
            out.extend_from_slice(b"\r\n");
        }
        self.io.write_all(&out).await.map_err(lost)?;
        self.io.flush().await.map_err(lost)?;
        let mut parser = Parser::default();
        loop {
            if let Some(reply) = parser.next(&self.buf)? {
                self.buf.advance(parser.position);
                return Ok(reply);
            }
            self.buf.reserve(8192);
            if self.io.read_buf(&mut self.buf).await.map_err(lost)? == 0 {
                return Err(Failure::Network("the server closed the connection".into()));
            }
        }
    }

    pub async fn close(mut self) {
        let _ = self.io.shutdown().await;
    }
}
