use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::path::Path;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use obfstr::obfstr;
use crate::cert_tools::{gen_cert_rsa2048, gen_rsa2048};


#[derive(Clone)]
pub struct MyRsaKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct ConfigObj {
    pub server_addr: String,
    pub server_port: u16,
    pub domain: String,
    pub req_host: String,
    pub req_port: u16,
    pub redis_url: String,
    pub redis_task_interval: u16,
    pub scope_ref_list: Vec<Uuid>,
    pub nls_service_instance_ref: Uuid,
    pub lease_time: u16,
    pub lease_renewal_factor: f32,
    pub cert_https: MyRsaKeyPair,
    pub rsa_client_token: MyRsaKeyPair,
    pub rsa_server_jwt: MyRsaKeyPair,
}


#[derive(Serialize, Deserialize, Debug)]
struct KeyPairPath {
    public_key: String,
    private_key: String,
}


#[derive(Serialize, Deserialize, Debug)]
struct ConfigData {
    server_addr: String,
    server_port: u16,
    domain: String,
    req_host: String,
    req_port: u16,
    redis_url: String,
    redis_task_interval: u16,
    scope_ref_list: Vec<Uuid>,
    nls_service_instance_ref: Uuid,
    lease_time: u16,
    lease_renewal_factor: u8,
    cert_https: KeyPairPath,
    rsa_client_token: KeyPairPath,
}


fn read_keypair(kp_path: &KeyPairPath, domain: Option<String>) -> MyRsaKeyPair {
    let public_key_path = Path::new(&kp_path.public_key);
    let private_key_path = Path::new(&kp_path.private_key);

    if (public_key_path.exists()) && (private_key_path.exists()) {
        MyRsaKeyPair {
            public_key: std::fs::read(&public_key_path).expect("failed to read key"),
            private_key: std::fs::read(&private_key_path).expect("failed to read key"),
        }
    } else {
        let gen_keypair;
        match domain {
            Some(domain) => {
                gen_keypair = gen_cert_rsa2048(domain);
            }
            None => {
                gen_keypair = gen_rsa2048();
            }
        }

        let mut public_key_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&public_key_path).expect("Unable to open public key file");
        public_key_file.write(&gen_keypair.public_key).expect("Unable to write public key file");

        let mut private_key_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&private_key_path).expect("Unable to open private key file");
        private_key_file.write(&gen_keypair.private_key).expect("Unable to write private key file");
        gen_keypair
    }
}


pub fn load_config() -> ConfigObj {
    let data_path = Path::new(".").join("data");
    let config_path = &data_path.join("config.json");
    if !&data_path.exists() {
        match std::fs::create_dir(&data_path) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Failed to make data dir!");
                std::process::exit(1);
            }
        };
    }


    let config_data: ConfigData = match OpenOptions::new()
        .read(true)
        .write(true)
        .append(false)
        .create(true)
        .open(&config_path) {
        Ok(mut file_obj) => {
            let inner_data: ConfigData = match serde_json::from_reader(&file_obj) {
                Ok(json_data) => json_data,
                Err(deserialize_error) => {
                    log::error!("Failed to parse config: {:?}", deserialize_error);
                    log::warn!("Using Default Setting.");

                    let default_configs = ConfigData {
                        server_addr: "127.0.0.1".to_string(),
                        server_port: 443,
                        req_host: "127.0.0.1".to_string(),
                        req_port: 443,
                        domain: "localhost".to_string(),
                        redis_url: "redis://127.0.0.1/".to_string(),
                        redis_task_interval: 30,
                        scope_ref_list: vec![Uuid::new_v4(), Uuid::new_v4()],
                        nls_service_instance_ref: Uuid::new_v4(),
                        lease_time: 1440,
                        lease_renewal_factor: 35,
                        cert_https: KeyPairPath {
                            public_key: "./data/https_cert.pem".to_string(),
                            private_key: "./data/https_key.pem".to_string(),
                        },
                        rsa_client_token: KeyPairPath {
                            public_key: "./data/token_cert.pem".to_string(),
                            private_key: "./data/token_key.pem".to_string(),
                        },
                    };
                    // set write to start and remove nul
                    let _ = &file_obj.set_len(0);
                    let _ = file_obj.rewind().unwrap();
                    match serde_json::to_writer_pretty(&file_obj, &default_configs) {
                        Ok(_) => {
                            log::warn!("Saved default config data.")
                        }
                        Err(_) => {
                            log::error!("Failed to save config data!")
                        }
                    };
                    default_configs
                }
            };
            inner_data
        }
        Err(file_error) => {
            log::error!("Failed to open config file: {:?}", file_error);
            std::process::exit(1);
        }
    };

    if config_data.lease_renewal_factor > 100 {
        log::error!("Config: failed to get lease_renewal_factor, value must be between 1 and 100!");
        std::process::exit(1);
    }


    obfstr! {
    let pub_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqd6EjBnZ68/Al/hQxCmz
5qW3eMXulTFYJb2WopgepjZCDvc2q/57qoekgVQEy9OwhXoXF8VnnTaoUaN7YZWA
r/woQ0Zkwe10FcWbT3Pju/DznqscmZPbSoru+SnUrxqZmzWeOo0q6l0w28tBZ2HC
+9ie95WHCfst/jVwZ+slsRAy7Uv5CwXeqIXubFhGwPV7+ICB2tmJiQPJcM+Y2tTK
FeaDyN9yKaUUjdjG80CGIKUnPdNCPEo/Cpf727rOCLl67kOd4mPmTrvyD0/nmREx
CQUSZt1smMFHR+uA11oN12I0yIy322gozwAyjd2r9Fok133/0EVTQqZ+ZmBExfor
3QIDAQAB
-----END PUBLIC KEY-----";
    let priv_key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqd6EjBnZ68/Al/hQxCmz5qW3eMXulTFYJb2WopgepjZCDvc2
q/57qoekgVQEy9OwhXoXF8VnnTaoUaN7YZWAr/woQ0Zkwe10FcWbT3Pju/Dznqsc
mZPbSoru+SnUrxqZmzWeOo0q6l0w28tBZ2HC+9ie95WHCfst/jVwZ+slsRAy7Uv5
CwXeqIXubFhGwPV7+ICB2tmJiQPJcM+Y2tTKFeaDyN9yKaUUjdjG80CGIKUnPdNC
PEo/Cpf727rOCLl67kOd4mPmTrvyD0/nmRExCQUSZt1smMFHR+uA11oN12I0yIy3
22gozwAyjd2r9Fok133/0EVTQqZ+ZmBExfor3QIDAQABAoIBAGEY7WD74eH15du4
N8p5H/kmHoKteRvUkdM41KLqGxLdDtNpIdocY+ntEO5P7VHpFgyl5g9Tak+mD35i
2ULFZ0Kw+v7BfRSQu3s6cfVvg+xI5ah7nKR4rK+mTMUl0QmqRcU/V8uWJ8LBNA1e
2GrUqdS1VOCmmwLsjbSyLSdpdSkI72pZYdP4FwF4MVfWu4gFrVf/vSxjy0l5wY/1
iCma0sjzS8npFP4Wf58PeBqbYUMJ/bCwPF+UYkx2xaRlAWWWtJsMdCQE4NBHqa1w
ZfHC5Y7oLjdYi0EDQeinqjnDIcKD/dedtDvrK5N3yL9D3VxiE0J2irzk9tNXvezf
S6lIqC0CgYEA333pptjB5DAZ+HihtziWSOvYPd3Ibz5BhUFqKJy9TjQh/IC7sVix
4ieKl4uLPWvURPZeWWJi56ncWQSwMLjTsVyIt49XKCzznLdHnHijb4kGHg+ycGpu
kT4pbjm+Dxts/ZifQHVlzmnRuBHb2S/s7Gk1XTn6AbCSZIUUPuLQ7pMCgYEAwpPg
t6Qto5M8cKG20x0SyBpkge3SJTXm4aahm+cQUAf3ylVX6MIqSTF6zwAjlP7mL8a8
ePFMHqwYZ2KRq/rrPwljmNHBMIx7Weh789S5q4meoa6yT2maQuA+7vRAmLqXwuLK
gz51mfAqFTbhGxLh2RpRicOK7CfC+byT3OF4kc8CgYAodGtR91SJkKdy0as8NjMF
+iMHd9jrQhKsI14rAcxGlqs8QLU48fwpGs08h1bqBFXFMe98MJIEqzumpXGbMCmp
pj1dNMYrEI/8YzTEPxYef2grEt5S+QEQq3bma+9aXrWI5hKVoWqPRZpfvmPUWZeC
Z7zwJil6GtM0/N3gUEBPnwKBgQCZeyoD0VZKtAY11emvhzxcaS0kq+JahbUUA2tw
3YepiU9043LPX/EZARWdGL/4dERAJWRfhf6EJz2stzyuyuMrOw276qCX2ggmuFKl
2AOJAqoFYRa3u1X6MIaT2Ejn8C9rg5c4hVkgTyfyyfIwd+l8Zd0xbPQ1KXwLoCuG
TLfdUwKBgHboiqjd22q6y753MUOFxr4TVHSOwYNTnzFjKyyjRZYXXz7r3e/xbVuW
Msgzaul+8rF3E83ZbR9u3Z2IURQZHKgA1e9rBMSf0dDnQ677oW/UubyoSHGwRuEV
BdLF6msAUzkXM1R1zS9Pk/5AVO54fj/HxYnsv+THMw8FvqGUMAz+
-----END RSA PRIVATE KEY-----";
        }

    let config_return = ConfigObj {
        server_addr: config_data.server_addr.clone(),
        server_port: config_data.server_port.clone(),
        domain: config_data.domain.clone(),
        req_host: config_data.req_host.clone(),
        req_port: config_data.req_port.clone(),
        redis_url: config_data.redis_url.clone(),
        redis_task_interval: config_data.redis_task_interval.clone(),
        scope_ref_list: config_data.scope_ref_list.clone(),
        nls_service_instance_ref: config_data.nls_service_instance_ref.clone(),
        lease_time: config_data.lease_time.clone(),
        lease_renewal_factor: f32::from(config_data.lease_renewal_factor.clone()) / 100.0,
        cert_https: read_keypair(&config_data.cert_https, Option::from(config_data.domain.clone())),
        rsa_client_token: read_keypair(&config_data.rsa_client_token, None),
        rsa_server_jwt: MyRsaKeyPair {
            public_key: pub_key.as_bytes().to_vec(),
            private_key: priv_key.as_bytes().to_vec(),
        },
    };
    config_return
}

pub async fn prepare_redis(connection_url: String) -> redis::Client {
    match redis::Client::open(connection_url) {
        Ok(redis_client) => {
            let _ = match redis_client.get_async_connection().await {
                Ok(conn)=> conn,
                Err(connection_error) =>{
                    log::error!("Failed to get redis connection! Cause: {}", connection_error);
                    std::process::exit(1);
                }
            };
            redis_client
        },
        Err(client_err) => {
            log::error!("Failed to open redis client! Cause: {}", client_err);
            std::process::exit(1);
        }
    }
}
