use crate::shared::{ConnectionUrl, Parts, encryption, multiple};

pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
    let example = "like cassandra://agent@10.0.0.1,10.0.0.2:9042/shop";
    let Parts {
        user,
        hosts,
        path: keyspace,
        query,
    } = multiple(text, 9042, false, example)?;
    let (tls, root_cert) = encryption(&query, "tls", "cassandra")?;
    Ok(ConnectionUrl {
        host: hosts[0].0.clone(),
        port: hosts[0].1,
        hosts,
        user,
        database: keyspace,
        tls,
        root_cert,
        text: text.to_string(),
    })
}
