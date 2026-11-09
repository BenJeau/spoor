use serde::Deserialize;
use std::time::Duration;

use crate::rfc6962::log_entry::LogEntry;

const REQUEST_TIMEOUT_SECS: u64 = 5;
static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub struct Client {
    http_client: reqwest::Client,
}

#[derive(Deserialize, Debug)]
struct RawEntries {
    entries: Vec<RawEntry>,
}

#[derive(Deserialize, Debug)]
pub(super) struct RawEntry {
    pub leaf_input: String,
    pub extra_data: String,
}

#[derive(Deserialize, Debug)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub timestamp: i64,
    pub sha256_root_hash: String,
    pub tree_head_signature: String,
}

impl Client {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .user_agent(APP_USER_AGENT)
                .build()?,
        })
    }

    pub async fn get_entries(
        &self,
        base_url: &str,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<anyhow::Result<LogEntry>>> {
        let base_url = base_url.trim_end_matches('/');
        let url = format!("{base_url}/ct/v1/get-entries?start={start}&end={end}");
        let response = self.http_client.get(url).send().await?.error_for_status()?;
        let entries = response.json::<RawEntries>().await?.entries;
        Ok(entries.into_iter().map(LogEntry::try_from).collect())
    }

    pub async fn get_signed_tree_head(&self, base_url: &str) -> anyhow::Result<SignedTreeHead> {
        let base_url = base_url.trim_end_matches('/');
        let url = format!("{base_url}/ct/v1/get-sth");
        let response = self.http_client.get(url).send().await?.error_for_status()?;
        Ok(response.json().await?)
    }
}
