use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Schema: https://www.gstatic.com/ct/log_list/v3/log_list_schema.json
pub const LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json";

impl LogList {
    pub async fn get() -> Result<Self, reqwest::Error> {
        reqwest::get(LOG_LIST_URL).await?.json().await
    }
}

#[derive(Deserialize, Serialize)]
pub struct LogList {
    pub version: String,
    pub log_list_timestamp: Timestamp,
    pub operators: Vec<Operator>,
}

#[derive(Deserialize, Serialize)]
pub struct Operator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
    pub tiled_logs: Vec<TiledLog>,
}

#[derive(Deserialize, Serialize)]
pub struct Log {
    #[serde(flatten)]
    pub common: BaseLog,
    pub url: String,
}

#[derive(Deserialize, Serialize)]
pub struct TiledLog {
    #[serde(flatten)]
    pub common: BaseLog,
    pub submission_url: String,
    pub monitoring_url: String,
}

#[derive(Deserialize, Serialize)]
pub struct BaseLog {
    pub description: Option<String>,
    pub key: String,
    pub log_id: String,
    pub mmd: u64,
    pub dns: Option<String>, // Hostname, should be parsed?
    pub temporal_interval: Option<TemporalInterval>,
    pub log_type: Option<LogType>,
    pub state: Option<State>,
    #[serde(default)]
    pub previous_operators: Vec<PreviousOperator>,
}

#[derive(Deserialize, Serialize)]
pub struct PreviousOperator {
    pub name: String,
    pub end_time: Timestamp,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogType {
    Test,
    Prod,
    MonitoringOnly,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Pending {
        timestamp: Timestamp,
    },
    Qualified {
        timestamp: Timestamp,
    },
    Usable {
        timestamp: Timestamp,
    },
    Readonly {
        timestamp: Timestamp,
        final_tree_head: FinalTreeHead,
    },
    Retired {
        timestamp: Timestamp,
    },
    Rejected {
        timestamp: Timestamp,
    },
}

impl State {
    pub fn kind(&self) -> String {
        match self {
            State::Rejected { .. } => "rejected".to_string(),
            State::Usable { .. } => "usable".to_string(),
            State::Pending { .. } => "pending".to_string(),
            State::Retired { .. } => "retired".to_string(),
            State::Qualified { .. } => "qualified".to_string(),
            State::Readonly { .. } => "readonly".to_string(),
        }
    }

    pub fn timestamp(&self) -> Timestamp {
        match self {
            State::Rejected { timestamp } => *timestamp,
            State::Usable { timestamp } => *timestamp,
            State::Pending { timestamp } => *timestamp,
            State::Retired { timestamp } => *timestamp,
            State::Qualified { timestamp } => *timestamp,
            State::Readonly { timestamp, .. } => *timestamp,
        }
    }

    pub fn final_tree_head_sha256_root_hash(&self) -> Option<String> {
        match self {
            State::Readonly {
                final_tree_head: final_tree_head,
                ..
            } => Some(final_tree_head.sha256_root_hash.clone()),
            _ => None,
        }
    }

    pub fn final_tree_head_tree_size(&self) -> Option<u64> {
        match self {
            State::Readonly {
                final_tree_head: final_tree_head,
                ..
            } => Some(final_tree_head.tree_size),
            _ => None,
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct FinalTreeHead {
    pub sha256_root_hash: String,
    pub tree_size: u64,
}

#[derive(Deserialize, Serialize)]
pub struct TemporalInterval {
    pub start_inclusive: Timestamp,
    pub end_exclusive: Timestamp,
}
