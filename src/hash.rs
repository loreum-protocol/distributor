use std::collections::HashMap;
use rand_core::{RngCore, CryptoRng, OsRng};
use vercel_lambda::{
    error::VercelError,
    http::{StatusCode, Version},
    lambda, IntoResponse, Request, Response,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use x25519_dalek::{EphemeralSecret, PublicKey};

static PUBLIC_KEY: &str = "0c222dd2f38d47376acaa7c59e9e6c340d3bf4224137c2280bd3ac03678bdd07";

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn parse_query(querystring: &str) -> HashMap<&str, &str> {
    let iter = querystring.split('&').map(|pair| {
        pair.split_once('=').unwrap()
    });
    HashMap::from_iter(iter)
}

fn handler(req: Request) -> Result<impl IntoResponse, VercelError> {
    // let query = parse_query(req.uri().query().unwrap());
    let edwards = CompressedEdwardsY::from_slice(&decode_hex(PUBLIC_KEY)).decompress().unwrap();
    let public_key = PublicKey::from(edwards.to_montgomery().to_bytes());
    let alice_secret = EphemeralSecret::new(OsRng);
    let pass = alice_secret.diffie_hellman(&public_key);
    let response = Response::builder()
        .version(Version::HTTP_2)
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(base64::encode(pass.as_bytes()))?;

    Ok(response)
}

fn main() {
    lambda!(handler)
}
