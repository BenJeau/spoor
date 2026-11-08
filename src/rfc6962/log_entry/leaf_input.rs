use base64::{Engine, prelude::BASE64_STANDARD};
use jiff::Timestamp;

use super::{Kind, certificate::Certificates};

#[derive(Debug)]
pub struct LeafInput {
    pub version: u8,
    pub leaf_kind: u8,
    pub timestamp: Timestamp,
    pub log_entry_kind: Kind,
    pub certificates: Certificates,
}

impl LeafInput {
    pub fn parse(data: String) -> anyhow::Result<Self> {
        let entry_buffer = BASE64_STANDARD.decode(data)?;
        let log_entry_kind = u16::from_be_bytes(entry_buffer[10..12].try_into()?).try_into()?;

        Ok(Self {
            version: entry_buffer[0],
            leaf_kind: entry_buffer[1],
            timestamp: Timestamp::from_millisecond(i64::from_be_bytes(
                entry_buffer[2..10].try_into()?,
            ))
            .unwrap(),
            log_entry_kind,
            certificates: parse_leaf_certificate(&entry_buffer[12..], log_entry_kind)?,
        })
    }
}

fn parse_leaf_certificate(data: &[u8], log_entry_kind: Kind) -> anyhow::Result<Certificates> {
    match log_entry_kind {
        Kind::X509 => Ok(Certificates::parse_chain_section(data)?.0),
        Kind::Precert => Ok(Default::default()),
    }
}
