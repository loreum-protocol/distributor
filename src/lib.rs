use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::prelude::*;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Message {
    nonce: Nonce,
    from: PublicKey,
    body: Vec<u8>,
}

pub fn private_key(seed: [u8; 32]) -> EphemeralSecret {
    EphemeralSecret::new(ChaCha20Rng::from_seed(seed))
}

fn random_nonce() -> Nonce {
    let mut bytes = [0; 12];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    Nonce::from(bytes)
}

pub fn decrypt(key: EphemeralSecret, message: &Message) -> Vec<u8> {
    let shared_key = key.diffie_hellman(&message.from);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared_key.as_bytes()));
    cipher
        .decrypt(&message.nonce, message.body.as_slice())
        .unwrap()
}

pub fn encrypt(key: EphemeralSecret, to: &PublicKey, body: &[u8]) -> Message {
    let from = PublicKey::from(&key);
    let shared_key = key.diffie_hellman(to);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared_key.as_bytes()));
    let nonce = random_nonce();
    let encrypted_body = cipher.encrypt(&nonce, body).unwrap();
    Message {
        nonce,
        from,
        body: encrypted_body,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::{Digest, Sha256};

    fn key_from_phrase(phrase: &str) -> EphemeralSecret {
        let mut hasher = Sha256::new();
        hasher.update(phrase);
        let hash = hasher.finalize();
        private_key(hash.into())
    }

    #[test]
    fn test_cyclic() {
        let alice_key = key_from_phrase("hoge");
        let bob_key = key_from_phrase("fuga");

        let message = encrypt(alice_key, &PublicKey::from(&bob_key), "hello".as_bytes());
        let decrypted = decrypt(bob_key, &message);
        assert_eq!(&String::from_utf8_lossy(&decrypted), "hello");
    }
}
