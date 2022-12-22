use actix_web::{get, post, put, delete, web, Result, Responder, HttpResponse, http::header::ContentType, Either};
use std::str::FromStr;

use num_traits::cast::ToPrimitive;
use sha2::{Sha256, Digest};
use uuid::{Uuid, uuid};
use time::OffsetDateTime;
use time::macros::format_description;
use rsa::{PublicKeyParts, RsaPublicKey};
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};


use crate::core_struct::{AppConfigState, NodeUrl, PortMap, PortSet, JwtAuthToken};
use crate::core_struct::origin::{OriginRequest, OriginResponse};
use crate::core_struct::code::{CodeRequest, CodeResponse, AcData};
use crate::core_struct::client_token::{ClientTokenRequest, ServiceInstanceConfiguration, ServiceInstancePublicKeyConfiguration, ServiceInstancePublicKeyMe};
use crate::core_struct::token::{AuthCode, TokenRequest, TokenResponse};
use crate::core_struct::leases::{ClientLeasesResponse, AddLessorResponse, CreateLeaseResult, LeaseCreateDetail, UpdateLeasesResponse, UpdateLeasesErrorResponse, DeleteLeasesResponse};


#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum ApiError {
    #[display(fmt = "Api Error: {}", detail)]
    InternalError { detail: String },
}

impl actix_web::error::ResponseError for ApiError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            ApiError::InternalError { .. } => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }
}


#[get("/genClientToken")]
pub async fn gen_client_token(config_state: web::Data<AppConfigState>) -> HttpResponse {
    let req_port = &config_state.req_port;
    let req_host = &config_state.req_host;
    let token_public_key_str = &config_state.rsa_client_token.public_key.clone();
    let token_public_key = RsaPublicKey::from_public_key_pem(std::str::from_utf8(token_public_key_str).expect("error read key")).expect("Error get public key");
    let key_modulus = token_public_key.n().clone();
    let key_exponent = token_public_key.e().clone();

    let current_time = OffsetDateTime::now_utc();
    let exp_time = current_time.clone() + std::time::Duration::from_secs(60 * 60 * 24 * 30);
    let client_token_obj = ClientTokenRequest {
        jti: Uuid::new_v4(),
        iss: "NLS Service Instance".to_string(),
        aud: "NLS Licensed Client".to_string(),
        iat: current_time.clone(),
        nbf: current_time.clone(),
        exp: exp_time,
        update_mode: "ABSOLUTE".to_string(),
        scope_ref_list: config_state.scope_ref_list.clone(),
        fulfillment_class_ref_list: None,
        service_instance_configuration: ServiceInstanceConfiguration {
            nls_service_instance_ref: config_state.nls_service_instance_ref.clone(),
            svc_port_set_list: vec![PortSet {
                idx: 0,
                d_name: "DLS".to_string(),
                svc_port_map: vec![
                    PortMap {
                        service: "auth".to_string(),
                        port: req_port.clone(),
                    }, PortMap {
                        service: "lease".to_string(),
                        port: req_port.clone(),
                    },
                ],
            }],
            node_url_list: vec![
                NodeUrl {
                    idx: 0,
                    url: req_host.clone(),
                    url_qr: req_host.clone(),
                    svc_port_set_idx: 0,
                }
            ],
        },
        service_instance_public_key_configuration: ServiceInstancePublicKeyConfiguration {
            service_instance_public_key_me: ServiceInstancePublicKeyMe { type_mod: format!("{:x}", key_modulus), exp: key_exponent.to_u32().unwrap() },
            service_instance_public_key_pem: token_public_key.to_public_key_pem(LineEnding::LF).unwrap(),
            key_retention_mode: "LATEST_ONLY".to_string(),
        },
    };

    let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);

    let client_token_str = jsonwebtoken::encode(
        &jwt_header,
        &client_token_obj,
        &jsonwebtoken::EncodingKey::from_rsa_pem(&config_state.rsa_client_token.private_key).expect("Error read jwt encode key!"),
    ).expect("Failed to encode jwt data!");

    let tok_format = format_description!("[day]-[month]-[year]-[hour]:[minute]:[second]");
    let tok_time = OffsetDateTime::now_utc().format(&tok_format).unwrap();
    HttpResponse::Ok()
        .content_type(ContentType::octet_stream())
        .append_header(("Content-Disposition", format!("attachment; filename=\"client_configuration_token_{}.tok\"", &tok_time)))
        .body(client_token_str.into_bytes())
}


#[post("/auth/v1/origin")]
pub async fn origin_req(origin_request: web::Json<OriginRequest>) -> Result<impl Responder> {
    let origin_response = OriginResponse {
        origin_ref: origin_request.candidate_origin_ref,
        environment: origin_request.environment.clone(),
        svc_port_set_list: None,
        node_url_list: None,
        node_query_order: None,
        prompts: None,
        sync_timestamp: OffsetDateTime::now_utc(),
    };
    Ok(web::Json(origin_response))
}


// todo error catch
#[post("/auth/v1/code")]
pub async fn code_req(code_request: web::Json<CodeRequest>, config_state: web::Data<AppConfigState>) -> Either<web::Json<CodeResponse>, Result<HttpResponse, ApiError>> {
    let time_now = OffsetDateTime::now_utc();
    let exp_time = time_now.clone() + std::time::Duration::from_secs(600);
    let code_challenge = code_request.code_challenge.clone();

    let ac_data = AcData {
        iat: time_now,
        exp: exp_time,
        challenge: code_challenge,
        origin_ref: code_request.origin_ref,
        key_ref: uuid!("00000000-0000-0000-0000-000000000000"),
        kid: uuid!("00000000-0000-0000-0000-000000000000"),
    };

    let mut jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    jwt_header.kid = Option::from("00000000-0000-0000-0000-000000000000".to_string());

    let auth_code = jsonwebtoken::encode(
        &jwt_header,
        &ac_data,
        &jsonwebtoken::EncodingKey::from_rsa_pem(&config_state.rsa_server_jwt.private_key).expect("Error read jwt encode key!"),
    ).expect("Failed to encode jwt data!");

    let code_resp = CodeResponse {
        auth_code,
        sync_timestamp: OffsetDateTime::now_utc(),
        prompts: None,
    };
    Either::Left(web::Json(code_resp))
}


#[post("/auth/v1/token")]
pub async fn auth_token(token_request: web::Json<TokenRequest>, config_state: web::Data<AppConfigState>) -> Either<web::Json<TokenResponse>, Result<HttpResponse, ApiError>> {
    // decode jwt
    let client_auth_code = match jsonwebtoken::decode::<AuthCode>(
        &token_request.auth_code,
        &jsonwebtoken::DecodingKey::from_rsa_pem(&config_state.rsa_server_jwt.public_key).expect("Error read jwt decode key"),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
    ) {
        Ok(data) => data,
        Err(decode_error) => {
            log::info!("jwt decode error!");
            return Either::Right(Err(ApiError::InternalError { detail: decode_error.to_string() }));
        }
    };

    // check challenge
    let code_verifier = token_request.code_verifier.clone();
    let mut hasher = Sha256::new();
    hasher.update(&code_verifier);
    let result = hasher.finalize();
    let b64_result = base64::encode(result).rsplit("=").collect::<String>();
    if b64_result != client_auth_code.claims.challenge {
        log::info!("Challenge failed!");
        return Either::Right(Err(ApiError::InternalError { detail: "Challenge Failed!".to_string() }));
    }


    let time_now = OffsetDateTime::now_utc();
    let exp_time = time_now.clone() + std::time::Duration::from_secs(60 * 60); // 1hr

    let auth_token = JwtAuthToken {
        iat: time_now.clone(),
        nbf: time_now.clone(),
        iss: "https://cls.nvidia.org".to_string(),
        aud: "https://cls.nvidia.org".to_string(),
        exp: exp_time.clone(),
        origin_ref: client_auth_code.claims.origin_ref,
        key_ref: client_auth_code.claims.key_ref,
        kid: client_auth_code.claims.kid,
    };


    let mut jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    jwt_header.kid = Option::from("00000000-0000-0000-0000-000000000000".to_string());

    let auth_token = jsonwebtoken::encode(
        &jwt_header,
        &auth_token,
        &jsonwebtoken::EncodingKey::from_rsa_pem(&config_state.rsa_server_jwt.private_key).expect("Error read jwt encode key!"),
    ).expect("Failed to encode jwt data!");

    let token_resp = TokenResponse {
        auth_token,
        expires: exp_time,
        prompts: None,
        sync_timestamp: time_now,
    };
    Either::Left(web::Json(token_resp))
}


// todo error catch
#[get("/v1/lessor/leases")]
pub async fn get_all_leases(jwt_auth_token: Option<web::ReqData<JwtAuthToken>>, redis_client: web::Data<redis::Client>) -> Result<impl Responder> {
    let time_now = OffsetDateTime::now_utc();

    let mut client_leases = ClientLeasesResponse {
        active_lease_list: vec![],
        prompts: None,
        sync_timestamp: time_now,
    };

    let origin_ref: Uuid = match jwt_auth_token {
        Some(data) => data.origin_ref,
        None => {
            return Ok(web::Json(client_leases));
        }
    };

    let mut redis_conn = redis_client.get_async_connection().await.expect("failed to get redis connection!");

    let lease_data: Vec<String> = redis::cmd("ZRANGEBYSCORE")
        .arg(&[
            origin_ref.to_string().as_str(),
            format!("({}", time_now.unix_timestamp()).as_str(),
            "+inf"
        ])
        .query_async(&mut redis_conn)
        .await.expect("unable to get redis");

    if lease_data.len() == 0 {
        return Ok(web::Json(client_leases));
    } else {
        for lease in lease_data {
            client_leases.active_lease_list.push(Uuid::from_str(lease.as_str()).unwrap());
        }
    }

    Ok(web::Json(client_leases))
}

#[post("/v1/lessor")]
pub async fn add_lessor(
    jwt_auth_token: Option<web::ReqData<JwtAuthToken>>,
    config_state: web::Data<AppConfigState>,
    redis_client: web::Data<redis::Client>,
) -> Either<web::Json<AddLessorResponse>, Result<HttpResponse, actix_web::Error>> {
    let origin_ref: Uuid = match jwt_auth_token {
        Some(data) => data.origin_ref,
        None => {
            return Either::Right(Ok(HttpResponse::Ok().content_type("application/json").body("none")));
        }
    };


    let time_now = OffsetDateTime::now_utc();
    let exp_time = time_now + time::Duration::minutes(i64::from(config_state.lease_time));

    let new_ref = Uuid::new_v4();

    let mut redis_conn = redis_client.get_async_connection().await.expect("failed to get redis connection!");
    let redis_status: i32 = redis::cmd("ZADD")
        .arg(&[
            origin_ref.to_string().as_str(),
            exp_time.unix_timestamp().to_string().as_str(),
            new_ref.to_string().as_str()
        ])
        .query_async(&mut redis_conn)
        .await.expect("unable to get redis");

    if !(redis_status == 1 || redis_status == 0) {
        return Either::Right(Ok(HttpResponse::Ok().content_type("application/json").body("none")));
    }
    let add_resp = AddLessorResponse {
        lease_result_list: vec![
            CreateLeaseResult {
                error: None,
                lease: LeaseCreateDetail {
                    type_ref: new_ref,
                    created: time_now,
                    expires: exp_time,
                    recommended_lease_renewal: config_state.lease_renewal_factor.clone(),
                    offline_lease: false,
                    license_type: "CONCURRENT_COUNTED_SINGLE".to_string(),
                },
                ordinal: None,
            }
        ],
        prompts: None,
        result_code: None,
        sync_timestamp: time_now,
    };
    Either::Left(web::Json(add_resp))
}

#[put("/v1/lease/{lease_ref}")]
pub async fn update_lessor(
    req_path: web::Path<Uuid>,
    jwt_auth_token: Option<web::ReqData<JwtAuthToken>>,
    config_state: web::Data<AppConfigState>,
    redis_client: web::Data<redis::Client>,
) -> Either<web::Json<UpdateLeasesResponse>, Result<HttpResponse, actix_web::Error>> {
    // env setup
    let time_now = OffsetDateTime::now_utc();
    let exp_time = time_now + time::Duration::minutes(i64::from(config_state.lease_time));
    let lease_ref = req_path.into_inner();
    let mut redis_conn = redis_client.get_async_connection().await.expect("failed to get redis connection!");

    let mut error_resp = UpdateLeasesErrorResponse {
        code: 404,
        message: "".to_string(),
        prompts: None,
        sync_timestamp: time_now,
    };

    // get ref from jwt
    let origin_ref: Uuid = match jwt_auth_token {
        Some(data) => data.origin_ref,
        None => {
            error_resp.code = 500;
            error_resp.message = format!("Unable to get origin_ref!");
            return Either::Right(Ok(HttpResponse::BadRequest().content_type("application/json").body(serde_json::to_string(&error_resp).unwrap())));
        }
    };

    // get all lease by ref from redis
    let lease_data: Vec<String> = redis::cmd("ZRANGEBYSCORE")
        .arg(&[
            origin_ref.to_string().as_str(),
            format!("({}", time_now.unix_timestamp()).as_str(),
            "+inf"
        ])
        .query_async(&mut redis_conn)
        .await.expect("unable to get redis");

    // check lease_ref in db or not
    if !lease_data.contains(&lease_ref.to_string()) {
        error_resp.message = format!("no current lease found for: {}", lease_ref);
        return Either::Right(Ok(HttpResponse::NotFound().content_type("application/json").body(serde_json::to_string(&error_resp).unwrap())));
    } else {
        // update the lease
        let redis_status: i32 = redis::cmd("ZADD")
            .arg(&[
                origin_ref.to_string().as_str(),
                exp_time.unix_timestamp().to_string().as_str(),
                lease_ref.to_string().as_str()
            ])
            .query_async(&mut redis_conn)
            .await.expect("unable to get redis");

        if !(redis_status == 1 || redis_status == 0) {
            error_resp.code = 500;
            error_resp.message = format!("Failed to update lease: {}", lease_ref);
            return Either::Right(Ok(HttpResponse::InternalServerError().content_type("application/json").body(serde_json::to_string(&error_resp).unwrap())));
        }
    }

    let update_resp = UpdateLeasesResponse {
        expires: exp_time,
        lease_ref: lease_ref,
        offline_lease: false,
        prompts: None,
        recommended_lease_renewal: config_state.lease_renewal_factor.clone(),
        sync_timestamp: time_now,
    };
    Either::Left(web::Json(update_resp))
}

#[delete("/v1/lessor/leases")]
pub async fn delete_all_leases(
    jwt_auth_token: Option<web::ReqData<JwtAuthToken>>,
    redis_client: web::Data<redis::Client>,
) -> Either<web::Json<DeleteLeasesResponse>, Result<HttpResponse, actix_web::Error>> {
    // env setup
    let time_now = OffsetDateTime::now_utc();
    let mut redis_conn = redis_client.get_async_connection().await.expect("failed to get redis connection!");

    // get ref from jwt
    let origin_ref: Uuid = match jwt_auth_token {
        Some(data) => data.origin_ref,
        None => {
            return Either::Right(Ok(HttpResponse::BadRequest().content_type("text/html").body("None")));
        }
    };

    let mut del_resp = DeleteLeasesResponse {
        release_failure_list: None,
        released_lease_list: vec![],
        prompts: None,
        sync_timestamp: time_now,
    };

    // get all lease by ref from redis
    let lease_data: Vec<String> = redis::cmd("ZRANGEBYSCORE")
        .arg(&[
            origin_ref.to_string().as_str(),
            format!("({}", time_now.unix_timestamp()).as_str(),
            "+inf"
        ])
        .query_async(&mut redis_conn)
        .await.expect("unable to get redis");

    if !lease_data.is_empty() {
        // delete the lease by ref
        let redis_status: i32 = redis::cmd("DEL")
            .arg(&[
                origin_ref.to_string().as_str(),
            ])
            .query_async(&mut redis_conn)
            .await.expect("unable to get redis");
        if redis_status != 1 {
            del_resp.release_failure_list = Some(lease_data.iter().map(|x| Uuid::from_str(x.as_str()).unwrap()).collect());
        }

        for lease in lease_data {
            del_resp.released_lease_list.push(Uuid::from_str(lease.as_str()).unwrap());
        }
    }

    Either::Left(web::Json(del_resp))
}