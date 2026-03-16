use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockSubscribeParams {
    commitment: String,
    encoding: String,
    transaction_details: Option<String>,
    max_supported_transaction_version: u8,
    show_rewards: bool,
}

impl Default for BlockSubscribeParams {
    fn default() -> Self {
        Self {
            commitment: "confirmed".into(),
            encoding: "base64".into(),
            transaction_details: Some("none".into()),
            max_supported_transaction_version: 0,
            show_rewards: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MinBlockNotif {
    pub value: MinBlockNotifValue,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MinBlockNotifValue {
    pub slot: u64,
    pub block: MinBlockNotifBlock,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MinBlockNotifBlock {
    pub blockhash: String,
}
