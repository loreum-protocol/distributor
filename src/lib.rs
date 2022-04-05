use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Message {
    nonce: Nonce,
    public_key: PublicKey,
    body: Vec<u8>,
}

static KEY: &[u8; 4] = b"hoge";

pub fn private_key() -> EphemeralSecret {
    let mut hasher = Sha256::new();
    hasher.update(KEY);
    let hash = hasher.finalize();
    EphemeralSecret::new(ChaCha20Rng::from_seed(hash.into()))
}

pub fn random_nonce() -> Nonce {
    let mut bytes = [0; 12];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    Nonce::from(bytes)
}

pub fn decrypt(key: EphemeralSecret, message: &Message) -> Vec<u8> {
    let shared_key = key.diffie_hellman(&message.public_key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared_key.as_bytes()));
    cipher
        .decrypt(&message.nonce, message.body.as_slice())
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    fn dummy_message() -> Message {
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&base64::decode("VtdcQo0osZno7E00").unwrap());

        let mut public_key = [0; 32];
        public_key.copy_from_slice(
            &base64::decode("79ToCqhhtYcrsysTavwL+DzhwfQ8WEftzXrOI0LV+XY=").unwrap(),
        );

        Message {
            nonce: Nonce::from(nonce),
            public_key: PublicKey::from(public_key),
            body: base64::decode("e1qeUfZLTTdNBw0Y8u1C8dRZ6fU=").unwrap(),
        }
    }

    #[test]
    fn test() {
        let message = dummy_message();
        let private_key = private_key();
        let result = decrypt(private_key, &message);
        assert_eq!(&String::from_utf8_lossy(&result), "hoge");
    }
}
