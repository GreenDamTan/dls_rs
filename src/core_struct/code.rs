use uuid::Uuid;
use serde::{Serialize, Deserialize};
use time::OffsetDateTime;
use time::serde as time_serde;

use crate::core_struct::LicenseProviderPrompt;


time_serde::format_description!(rfc3339_ms_z, OffsetDateTime, "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodeRequest {
    pub code_challenge: String,
    pub origin_ref: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CodeResponse {
    // jwt
    pub auth_code: String,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AcData {
    #[serde(with = "time::serde::timestamp")]
    pub iat: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub exp: OffsetDateTime,
    pub challenge: String,
    pub origin_ref: Uuid,
    pub key_ref: Uuid,
    pub kid: Uuid,
}
