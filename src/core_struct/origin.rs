use uuid::Uuid;
use serde::{Serialize, Deserialize};
use time::OffsetDateTime;
use time::serde as time_serde;
use crate::core_struct::{LicenseProviderPrompt, NodeUrl, PortSet};

time_serde::format_description!(rfc3339_ms_z, OffsetDateTime, "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");

#[derive(Serialize, Deserialize, Debug)]
pub struct OriginRequest {
    pub environment: EnvironmentData,
    pub candidate_origin_ref: Uuid,
    pub registration_pending: bool,
    pub update_pending: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnvironmentData {
    pub fingerprint: FingerprintData,
    pub guest_driver_version: String,
    pub hostname: String,
    pub os_platform: String,
    pub os_version: String,
    pub ip_address_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FingerprintData {
    pub mac_address_list: Vec<String>,
}


#[derive(Serialize, Debug)]
pub struct OriginResponse {
    pub origin_ref: Uuid,
    pub environment: EnvironmentData,
    pub svc_port_set_list: Option<Vec<PortSet>>,
    pub node_url_list: Option<Vec<NodeUrl>>,
    pub node_query_order: Option<Vec<u8>>,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}
