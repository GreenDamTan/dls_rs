use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::serde as time_serde;
use uuid::Uuid;
use crate::core_struct::LicenseProviderPrompt;

time_serde::format_description!(rfc3339_ms_z, OffsetDateTime, "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenRequest {
    pub auth_code: String,
    pub code_verifier: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct AuthCode {
    #[serde(with = "time::serde::timestamp")]
    pub iat: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub exp: OffsetDateTime,
    pub challenge: String,
    pub origin_ref: Uuid,
    pub key_ref: Uuid,
    pub kid: Uuid,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct TokenResponse {
    pub auth_token: String,
    #[serde(with = "rfc3339_ms_z")]
    pub expires: OffsetDateTime,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct TokenErrorResponse {
    pub code: u16,
    pub message: String,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}