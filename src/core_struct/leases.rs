use uuid::Uuid;
use serde::{Serialize, Deserialize};
use time::OffsetDateTime;
use time::serde as time_serde;

use crate::core_struct::LicenseProviderPrompt;


time_serde::format_description!(rfc3339_ms_z, OffsetDateTime, "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");
time_serde::format_description!(rfc3339_ms, OffsetDateTime, "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]");


#[derive(Serialize, Deserialize, Debug)]
pub struct ClientLeasesResponse {
    pub active_lease_list: Vec<Uuid>,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientLeasesErrorResponse {
    pub detail: String,
    pub status: u32,
    pub title: String,
    #[serde(rename = "type")]
    pub error_type: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct AddLessorResponse {
    pub lease_result_list: Vec<CreateLeaseResult>,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    // one of "SUCCESS", "FULFILLMENT_FAILURE", "INVALID_LEASE_PROPOSAL", "UNKNOWN_ACCESS_GROUP", "INFRASTRUCTURE_FAILURE", or None -> SUCCESS
    pub result_code: Option<String>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateLeaseResult {
    pub error: Option<String>,
    pub lease: LeaseCreateDetail,
    pub ordinal: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LeaseCreateDetail {
    #[serde(rename = "ref")]
    pub type_ref: Uuid,
    #[serde(with = "rfc3339_ms")]
    pub created: OffsetDateTime,
    #[serde(with = "rfc3339_ms")]
    pub expires: OffsetDateTime,
    pub recommended_lease_renewal: f32,
    pub offline_lease: bool,
    // default to CONCURRENT_COUNTED_SINGLE now, seem apply for all req
    pub license_type: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateLeasesResponse {
    #[serde(with = "rfc3339_ms_z")]
    pub expires: OffsetDateTime,
    pub lease_ref: Uuid,
    pub offline_lease: bool,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    pub recommended_lease_renewal: f32,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateLeasesErrorResponse {
    pub message: String,
    pub code: u16,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteLeasesResponse {
    pub release_failure_list: Option<Vec<Uuid>>,
    pub released_lease_list: Vec<Uuid>,
    pub prompts: Option<Vec<LicenseProviderPrompt>>,
    #[serde(with = "rfc3339_ms_z")]
    pub sync_timestamp: OffsetDateTime,
}
