pub mod origin;
pub mod code;
pub mod client_token;
pub mod token;
pub mod leases;

use uuid::Uuid;
use serde::{Serialize, Deserialize};
use time::OffsetDateTime;
use crate::utils::MyRsaKeyPair;


#[derive(Clone)]
pub struct AppConfigState {
    pub req_port: u16,
    pub req_host: String,
    pub scope_ref_list: Vec<Uuid>,
    pub nls_service_instance_ref: Uuid,
    pub lease_time: u16,
    pub lease_renewal_factor: f32,
    pub rsa_client_token: MyRsaKeyPair,
    pub rsa_server_jwt: MyRsaKeyPair,
}

#[derive(Clone)]
pub struct RedisTaskConfig {
    pub redis_url: String,
    pub task_interval: u16,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct PortSet {
    pub idx: u8,
    pub d_name: String,
    pub svc_port_map: Vec<PortMap>,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct PortMap {
    pub service: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeUrl {
    pub idx: u8,
    pub url: String,
    pub url_qr: String,
    pub svc_port_set_idx: u8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LicenseProviderPrompt {
    // datetime
    pub ts: String,
    pub prompt_ref: String,
    pub operation_type: String,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtAuthToken {
    #[serde(with = "time::serde::timestamp")]
    pub iat: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub nbf: OffsetDateTime,
    pub iss: String,
    pub aud: String,
    #[serde(with = "time::serde::timestamp")]
    pub exp: OffsetDateTime,
    pub origin_ref: Uuid,
    pub key_ref: Uuid,
    pub kid: Uuid,
}