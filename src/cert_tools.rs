#![allow(clippy::complexity, clippy::style, clippy::pedantic)]

use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;

use rcgen::{Certificate, CertificateParams, DistinguishedName, date_time_ymd, DnType};
use std::convert::TryFrom;
use crate::utils::MyRsaKeyPair;


pub fn gen_rsa2048() -> MyRsaKeyPair {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let pub_key_str = pub_key.to_public_key_pem(LineEnding::LF).unwrap();
    let priv_key_str = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str().to_owned();

    MyRsaKeyPair {
        public_key: pub_key_str.into_bytes(),
        private_key: priv_key_str.into_bytes(),
    }
}


pub fn gen_cert_rsa2048(common_name: String) -> MyRsaKeyPair {
    let mut params: CertificateParams = Default::default();
    params.not_before = date_time_ymd(2021, 01, 01);
    params.not_after = date_time_ymd(2030, 12, 30);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.distinguished_name.push(DnType::OrganizationalUnitName, "Server Cert");
    params.distinguished_name.push(DnType::OrganizationName, "ORG");
    params.distinguished_name.push(DnType::CountryName, "RS");

    params.alg = &rcgen::PKCS_RSA_SHA256;


    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to gen private key!");
    let private_key_der = private_key.to_pkcs8_der().unwrap();
    let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params).expect("Failed to gen cert!");
    let pem_serialized = cert.serialize_pem().unwrap();

    let cert_str = pem_serialized;
    let cert_key = cert.serialize_private_key_pem();

    MyRsaKeyPair {
        public_key: cert_str.into_bytes(),
        private_key: cert_key.into_bytes(),
    }
}