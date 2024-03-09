extern crate sha2;
extern crate rand;
extern crate num_bigint;

use num_traits::Zero;
use num_bigint::{BigUint, RandBigInt};
use sha2::{Digest, Sha256};

fn new_random_uint(bit_length: u16) -> BigUint {
    let mut rng = rand::thread_rng();
    let random_bits = rng.gen_biguint(bit_length as u64);
    random_bits
}

struct SRP6Base {
    session_key: BigUint,
    private_key: BigUint,
    public_key: BigUint,
    salt: BigUint,
    multiplier_k: BigUint,
    identity_hash: BigUint,
    generator_g: BigUint,
    scrambler: BigUint,
}

impl SRP6Base {
    fn new() -> SRP6Base {
        SRP6Base {
            session_key: BigUint::zero(),
            private_key: BigUint::zero(),
            public_key: BigUint::zero(),
            salt: BigUint::zero(),
            multiplier_k: BigUint::from(3u32),
            identity_hash: BigUint::zero(),
            generator_g: BigUint::zero(),
            scrambler: BigUint::zero(),
        }
    }

    fn get_public_key(&self) -> &BigUint {
        &self.public_key
    }

    fn get_private_key(&self) -> &BigUint {
        &self.private_key
    }

    fn get_session_key(&self) -> &BigUint {
        &self.session_key
    }

    fn get_salt(&self) -> &BigUint {
        &self.salt
    }

    fn get_multiplier(&self) -> &BigUint {
        &self.multiplier_k
    }

    fn get_identity_hash(&self) -> &BigUint {
        &self.identity_hash
    }

    fn get_generator(&self) -> &BigUint {
        &self.generator_g
    }

    fn get_scrambler(&self) -> &BigUint {
        &self.scrambler
    }
}

struct SRP6Server {
    base: SRP6Base,
    modulus_n: BigUint,
    s_verifier: BigUint,
}

impl SRP6Server {
    fn new(
        user: &str,
        password: &str,
        modulus_n: &str,
        generator_g: u32,
        salt_bits: u16,
        scrambler_bits: u16,
    ) -> SRP6Server {
        let mut base = SRP6Base::new();
        let modulus_n = BigUint::parse_bytes(modulus_n.as_bytes(), 16).unwrap();
        base.generator_g = BigUint::from(generator_g);
        base.salt = new_random_uint(salt_bits);
        base.scrambler = new_random_uint(scrambler_bits);

        let salt_hex = base.salt.to_str_radix(16);
        let hash_input = format!("{}{}:{}", salt_hex, user, password);

        // Set the base identity hash
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let hash_result = hasher.finalize();
        base.identity_hash = BigUint::from_bytes_be(&hash_result);
            

        let s_verifier = base
            .generator_g
            .modpow(&base.identity_hash, &modulus_n);

        base.private_key = new_random_uint(128);

        let public_key = &base
            .multiplier_k
            * &s_verifier +
            &base.generator_g.modpow(&base.private_key, &modulus_n);
        base.public_key = public_key;

        SRP6Server {
            base,
            modulus_n: modulus_n.clone(),
            s_verifier,
        }
    }

    fn set_session_key(&mut self, public_key: &BigUint) {
        let temp = public_key
            * &self.s_verifier.modpow(&self.base.scrambler, &self.modulus_n);
        self.base.session_key = temp.modpow(&self.base.private_key, &self.modulus_n);
    }

    fn get_identity_hash(&self) -> &BigUint {
        &self.base.identity_hash
    }

    fn get_modulus(&self) -> &BigUint {
        &self.modulus_n
    }

    fn get_verifier(&self) -> &BigUint {
        &self.s_verifier
    }
}

struct SRP6Client {
    base: SRP6Base,
    modulus_n: BigUint,
}

impl SRP6Client {
    fn new(
        user: &str,
        password: &str,
        modulus_n: &str,
        generator_g: u32,
        salt: &BigUint,
    ) -> SRP6Client {
        let mut base = SRP6Base::new();
        let modulus_n = BigUint::parse_bytes(modulus_n.as_bytes(), 16).unwrap();
        base.generator_g = BigUint::from(generator_g);
        base.salt = salt.clone();
        base.session_key = BigUint::zero();

        base.private_key = new_random_uint(128);         

        let public_key = base.generator_g.modpow(&base.private_key, &modulus_n);
        base.public_key = public_key;

        let salt_hex = base.salt.to_str_radix(16);
        let hash_input = format!("{}{}:{}", salt_hex, user, password);
        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let hash_result = hasher.finalize();
        let identity_hash = BigUint::from_bytes_be(&hash_result);
        base.identity_hash = identity_hash;

        SRP6Client {
            base,
            modulus_n: modulus_n.clone(),
        }
    }

    fn set_session_key(&mut self, pub_key: &BigUint, scram: &BigUint) {
        self.base.public_key = pub_key.clone();
        self.base.scrambler = scram.clone();
        let temp = &self.base.private_key + (&self.base.scrambler * &self.base.identity_hash);
        let subtraction = pub_key - 
            &self.base.generator_g.modpow(
                &self.base.identity_hash,
                &self.modulus_n,
            ) *
            &self.base.multiplier_k;
        self.base.session_key = subtraction.modpow(&temp, &self.modulus_n);
    }
}

fn main() {
    let modulus = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";

    let mut srp_server = SRP6Server::new("TEST", "test", modulus, 2, 256, 128);
    let mut srp_client = SRP6Client::new("TEST", "test", modulus, 2, srp_server.base.get_salt());

    srp_server.set_session_key(srp_client.base.get_public_key());
    srp_client.set_session_key(
        srp_server.base.get_public_key(),
        srp_server.base.get_scrambler(),
    );

    println!("=== SRP6 Demo Started ===");
    println!("Modulus = {}", srp_server.get_modulus());
    println!("Multiplier = {}", srp_server.base.get_multiplier());
    println!("Generator = {}", srp_server.base.get_generator());
    println!("Salt = {}", srp_server.base.get_salt());
    println!("IdentityHash = {}", srp_server.get_identity_hash());
    println!("Verifier = {}", srp_server.get_verifier());
    println!();
    println!("ServerPrivateKey (b) = {}", srp_server.base.get_private_key());
    println!("ServerPublicKey (B) = {}", srp_server.base.get_public_key());
    println!("Scrambler (u) = {}", srp_server.base.get_scrambler());
    println!();
    println!("ClientPrivateKey (a) = {}", srp_client.base.get_private_key());
    println!("ClientPublicKey (A)= {}", srp_client.base.get_public_key());
    println!("ClientIdentityHash (x) = {}", srp_client.base.get_identity_hash());
    println!();
    println!("ServerSessionKey = {}", srp_server.base.get_session_key());
    println!("ClientSessionKey = {}", srp_client.base.get_session_key());
    println!();
    let passed = srp_server.base.get_session_key() == srp_client.base.get_session_key();
    println!(
        "Test Results: {}",
        if passed { "PASSED!" } else { "FAILED!" }
    );
}