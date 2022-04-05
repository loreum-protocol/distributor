use x25519_dalek::{PublicKey, EphemeralSecret};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use sha2::{Sha256, Digest};


struct Message {
    public_key: PublicKey,
    body: Vec<u8>,
}

static KEY: &[u8; 4] = b"hoge";

fn private_key() -> EphemeralSecret {
    let mut hasher = Sha256::new();
    hasher.update(KEY);
    let hash = hasher.finalize();
    EphemeralSecret::new(ChaCha20Rng::from_seed(hash.into()))
}

#[cfg(test)]
mod test {
    use super::*;

    fn dummy_message() -> Message {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&base64::decode("79ToCqhhtYcrsysTavwL+DzhwfQ8WEftzXrOI0LV+XY=").unwrap());
        Message {
            public_key: PublicKey::from(bytes),
            body: Vec::new(),
        }
    }

    #[test]
    fn test_shared_key() {
        let message = dummy_message();
        let private_key = private_key();
        let shared_key = private_key.diffie_hellman(&message.public_key);
    }
}
