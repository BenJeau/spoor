use jiff::Timestamp;

use crate::rfc6962::client::RawEntry;

pub mod certificate;
mod extra_data;
mod leaf_input;
mod utils;

#[derive(Debug)]
pub struct LogEntry {
    pub version: u8,
    pub leaf_kind: u8,
    pub timestamp: Timestamp,
    pub log_entry_kind: Kind,
    pub certificates: certificate::Certificates,
}

impl TryFrom<RawEntry> for LogEntry {
    type Error = anyhow::Error;

    fn try_from(raw_entry: RawEntry) -> Result<Self, Self::Error> {
        let leaf_input = leaf_input::LeafInput::parse(raw_entry.leaf_input)?;
        let extra_data =
            extra_data::ExtraData::parse(raw_entry.extra_data, leaf_input.log_entry_kind)?;

        let mut certificates = leaf_input.certificates;
        certificates.0.extend(extra_data.certificates.0);

        Ok(Self {
            version: leaf_input.version,
            leaf_kind: leaf_input.leaf_kind,
            timestamp: leaf_input.timestamp,
            log_entry_kind: leaf_input.log_entry_kind,
            certificates,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    X509,
    Precert,
}

impl TryFrom<u16> for Kind {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Kind::X509),
            1 => Ok(Kind::Precert),
            _ => Err(anyhow::anyhow!("Unknown log entry kind")),
        }
    }
}
