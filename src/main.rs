mod utils;
mod cert_tools;
mod core_struct;
mod api;

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use actix_web::{get, web, App, Error, HttpServer, Responder, HttpResponse, middleware, dev::ServiceRequest, HttpMessage};

use actix_web_httpauth::{
    extractors::bearer::BearerAuth,
    middleware::HttpAuthentication,
};

use rustls::{Certificate, PrivateKey, ServerConfig};
use time::OffsetDateTime;

use crate::utils::{load_config, prepare_redis};
use crate::core_struct::{AppConfigState, JwtAuthToken, RedisTaskConfig};
use crate::api::{add_lessor, auth_token, code_req, delete_all_leases, gen_client_token, get_all_leases, origin_req, update_lessor};
use crate::core_struct::leases::ClientLeasesErrorResponse;


#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}


// todo impl new type for json error
async fn leases_validator(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let config_state = req.app_data::<web::Data<AppConfigState>>().cloned().expect("Server Error");

    // decode jwt
    let client_auth_token = match jsonwebtoken::decode::<JwtAuthToken>(
        &credentials.token(),
        &jsonwebtoken::DecodingKey::from_rsa_pem(&config_state.rsa_server_jwt.public_key).expect("Error read jwt decode key"),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
    ) {
        Ok(token_data) => token_data,
        Err(jwt_error) => {
            let error_resp = ClientLeasesErrorResponse {
                detail: jwt_error.to_string(),
                status: 401,
                title: "Unauthorized".to_string(),
                error_type: "about:blank".to_string(),
            };
            let new_error = actix_web::error::ErrorUnauthorized(serde_json::to_string_pretty(&error_resp).unwrap());
            return Err((new_error, req));
        }
    };
    req.extensions_mut().insert(client_auth_token.claims);
    Ok(req)
}


async fn async_clean_lease(task_config: RedisTaskConfig, shutdown_marker: Arc<AtomicBool>) -> std::io::Result<()> {
    let job_interval = i64::from(task_config.task_interval) * 60;
    let start_time = OffsetDateTime::now_utc();

    loop {
        if shutdown_marker.load(Ordering::SeqCst) {
            log::info!("RedisTask Stop.");
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        if ((OffsetDateTime::now_utc() - start_time).whole_seconds() % job_interval) != 0 {
            continue
        }

        let _ = match redis::Client::open(task_config.redis_url.clone().as_str()) {
            Ok(redis_client) => {
                let _ = match redis_client.get_async_connection().await {
                    Ok(mut redis_connection) => {
                        let _ = match redis::cmd("keys").arg(&["*"]).query_async::<_, Vec<String>>(&mut redis_connection).await {
                            Ok(ref_list) => {
                                let time_now = OffsetDateTime::now_utc();
                                for ref_id in ref_list {
                                    let _ = match redis::cmd("ZREMRANGEBYSCORE")
                                        .arg(&[
                                            ref_id.as_str(),
                                            "0",
                                            time_now.unix_timestamp().to_string().as_str()
                                        ])
                                        .query_async::<_, i32>(&mut redis_connection)
                                        .await {
                                        Ok(redis_status) => {
                                            if redis_status != 0 {
                                                log::info!("RedisTask: ref: {} clean with {} leases.", &ref_id, &redis_status);
                                            }
                                        }
                                        Err(redis_err) => {
                                            log::debug!("RedisTask: cannot remove ref: {}, Cause: {}", &ref_id, redis_err);
                                        }
                                    };
                                }
                            }
                            Err(redis_err) => {
                                log::debug!("RedisTask: Cannot get keys! Cause: {}", redis_err);
                            }
                        };
                    }
                    Err(_) => {
                        log::debug!("RedisTask: Cannot open redis connection!")
                    }
                };
            }
            Err(_) => {
                log::debug!("RedisTask: Cannot open redis client!")
            }
        };
        log::debug!("RedisTask cleanup done.");
    }
    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // log setting
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    // startup check
    let config_data = load_config();
    let redis_client = web::Data::new(prepare_redis(config_data.redis_url.clone()).await);
    let task_config = RedisTaskConfig {
        redis_url: config_data.redis_url.clone(),
        task_interval: config_data.redis_task_interval.clone(),
    };

    let shared_data = web::Data::new(AppConfigState {
        req_host: config_data.req_host.clone(),
        req_port: config_data.req_port.clone(),
        scope_ref_list: config_data.scope_ref_list,
        nls_service_instance_ref: config_data.nls_service_instance_ref,
        lease_time: config_data.lease_time,
        lease_renewal_factor: config_data.lease_renewal_factor,
        rsa_client_token: config_data.rsa_client_token,
        rsa_server_jwt: config_data.rsa_server_jwt,
    });


    // tls content
    let public_key_der = pem::parse(&config_data.cert_https.public_key).unwrap().contents;
    let private_key_der = pem::parse(&config_data.cert_https.private_key).unwrap().contents;

    let public_key = vec![Certificate(public_key_der)];
    let private_key = PrivateKey(private_key_der);

    // configure certificate and private key used by https
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(public_key, private_key)
        .unwrap();


    // paste server addr and port
    let bind_addr: SocketAddr = match format!("{}:{}", &config_data.server_addr, &config_data.server_port).parse() {
        Ok(addr) => {
            log::info!("starting HTTPS server at https://{}", addr);
            addr
        }
        _ => {
            log::error!("Error read bind address and port!");
            std::process::exit(1);
        }
    };

    let server = HttpServer::new(move || {
        let leases_auth = HttpAuthentication::bearer(leases_validator);
        let leasing_scope = web::scope("/leasing")
            .service(get_all_leases)
            .service(add_lessor)
            .service(update_lessor)
            .service(delete_all_leases)
            .wrap(leases_auth);

        App::new()
            .wrap(middleware::Logger::default())
            .service(hello)
            .service(gen_client_token)
            .service(origin_req)
            .service(code_req)
            .service(auth_token)
            .service(leasing_scope)
            .app_data(shared_data.clone())
            .app_data(redis_client.clone())
    })
        .keep_alive(std::time::Duration::from_secs(5))
        .bind_rustls(bind_addr, tls_config)?
        .workers(2)
        .run();

    let server_handle = server.handle();
    let task_shutdown_marker = Arc::new(AtomicBool::new(false));

    // create my task
    let server_task = tokio::spawn(server);
    let worker_task = tokio::spawn(async_clean_lease(task_config, Arc::clone(&task_shutdown_marker)));

    let shutdown = tokio::spawn(async move {
        // listen for ctrl-c
        tokio::signal::ctrl_c().await.unwrap();

        // start shutdown of tasks
        let server_stop = server_handle.stop(true);
        task_shutdown_marker.store(true, Ordering::SeqCst);

        // await shutdown of tasks
        server_stop.await;
    });

    let _ = tokio::try_join!(server_task, worker_task, shutdown).expect("unable to join tasks");

    Ok(())
}
