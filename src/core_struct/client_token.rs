use uuid::Uuid;
use serde::{Serialize, Deserialize};
use time::OffsetDateTime;
use time::serde as time_serde;
use crate::core_struct::{NodeUrl, PortSet};

time_serde::format_description!(rfc3339_ms_z, OffsetDateTime, "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");


#[derive(Serialize, Deserialize, Debug)]
pub struct ClientTokenRequest {
    pub jti: Uuid,
    pub iss: String,
    pub aud: String,
    #[serde(with = "time::serde::timestamp")]
    pub iat: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub nbf: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub exp: OffsetDateTime,
    // TODO should come from UI as param
    pub update_mode: String,
    pub scope_ref_list: Vec<Uuid>,
    pub fulfillment_class_ref_list: Option<Vec<String>>,
    pub service_instance_configuration: ServiceInstanceConfiguration,
    pub service_instance_public_key_configuration: ServiceInstancePublicKeyConfiguration,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceInstanceConfiguration {
    pub nls_service_instance_ref: Uuid,
    pub svc_port_set_list: Vec<PortSet>,
    pub node_url_list: Vec<NodeUrl>,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceInstancePublicKeyConfiguration {
    pub service_instance_public_key_me: ServiceInstancePublicKeyMe,
    pub service_instance_public_key_pem: String,
    pub key_retention_mode: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceInstancePublicKeyMe {
    #[serde(rename = "mod")]
    pub type_mod: String,
    pub exp: u32,
}