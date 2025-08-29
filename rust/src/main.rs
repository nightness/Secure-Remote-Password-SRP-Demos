extern crate num_bigint;
extern crate rand;

mod sha3_custom;
mod sha3_test;

mod srp {
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::Zero;
    use rand::thread_rng;
    use crate::sha3_custom::SHA3_256;

    struct Base {
        modulus_n: BigUint,
        session_key: BigUint,
        private_key: BigUint,
        public_key: BigUint,
        salt: BigUint,
        multiplier_k: BigUint,
        identity_hash: BigUint,
        generator_g: BigUint,
        scrambler: BigUint,
    }

    impl Base {
        pub fn new(modulus_n: &str, multiplier_k: u32, generator_g: u32, key_size: u16) -> Base {
            let modulus_n = BigUint::parse_bytes(modulus_n.as_bytes(), 16).unwrap();
            let generator_g = BigUint::from(generator_g);
            let multiplier_k = BigUint::from(multiplier_k);
            let mut rng = thread_rng();
            let private_key = rng.gen_biguint(key_size as u64);

            Base {
                modulus_n,
                session_key: BigUint::zero(),
                private_key,
                public_key: BigUint::zero(),
                salt: BigUint::zero(),
                multiplier_k,
                identity_hash: BigUint::zero(),
                generator_g,
                scrambler: BigUint::zero(),
            }
        }

        pub fn set_salt(&mut self, salt: &BigUint) {
            self.salt = salt.clone();
        }

        pub fn generate_salt(&mut self, bits: u16) {
            let mut rng = thread_rng();
            self.salt = rng.gen_biguint(bits as u64);
        }

        pub fn generate_scrambler(&mut self, bits: u16) {
            let mut rng = thread_rng();
            self.scrambler = rng.gen_biguint(bits as u64);
        }

        pub fn compute_identity_hash(&mut self, user: &str, password: &str) {
            let salt_hex = self.salt.to_str_radix(16);
            let hash_input = format!("{}{}:{}", salt_hex, user, password);
            let hash_hex = SHA3_256::hash_string(&hash_input);
            self.identity_hash = BigUint::parse_bytes(hash_hex.as_bytes(), 16).unwrap_or_default();
        }
    }

    pub struct Server {
        base: Base,
        s_verifier: BigUint,
    }

    impl Server {
        pub fn new(
            user: &str,
            password: &str,
            modulus_n: &str,
            multiplier_k: u32,
            generator_g: u32,
            salt_bits: u16,
            scrambler_bits: u16,
            key_size: u16,
        ) -> Server {
            let mut base = Base::new(modulus_n, multiplier_k, generator_g, key_size);
            base.generate_salt(salt_bits);
            base.generate_scrambler(scrambler_bits);
            base.compute_identity_hash(user, password);

            let s_verifier = base
                .generator_g
                .modpow(&base.identity_hash, &base.modulus_n);

            base.public_key = &base.multiplier_k * &s_verifier
                + &base.generator_g.modpow(&base.private_key, &base.modulus_n);

            Server { base, s_verifier }
        }

        pub fn compute_session_key(&mut self, public_key: &BigUint) {
            let temp = public_key
                * &self
                    .s_verifier
                    .modpow(&self.base.scrambler, &self.base.modulus_n);
            self.base.session_key = temp.modpow(&self.base.private_key, &self.base.modulus_n);
        }

        pub fn get_identity_hash(&self) -> &BigUint {
            &self.base.identity_hash
        }

        pub fn get_public_key(&self) -> &BigUint {
            &self.base.public_key
        }

        pub fn get_scrambler(&self) -> &BigUint {
            &self.base.scrambler
        }

        pub fn get_salt(&self) -> &BigUint {
            &self.base.salt
        }

        pub fn get_private_key(&self) -> &BigUint {
            &self.base.private_key
        }

        pub fn get_session_key(&self) -> &BigUint {
            &self.base.session_key
        }

        pub fn get_multiplier(&self) -> &BigUint {
            &self.base.multiplier_k
        }

        pub fn get_generator(&self) -> &BigUint {
            &self.base.generator_g
        }

        pub fn get_modulus(&self) -> &BigUint {
            &self.base.modulus_n
        }

        pub fn get_verifier(&self) -> &BigUint {
            &self.s_verifier
        }
    }

    pub struct Client {
        base: Base,
    }

    impl Client {
        pub fn new(
            user: &str,
            password: &str,
            modulus_n: &str,
            multiplier_k: u32,
            generator_g: u32,
            salt: &BigUint,
            key_size: u16,
        ) -> Client {
            let mut base = Base::new(modulus_n, multiplier_k, generator_g, key_size);
            base.set_salt(salt);
            base.compute_identity_hash(user, password);

            base.public_key = base.generator_g.modpow(&base.private_key, &base.modulus_n);

            Client { base }
        }

        pub fn compute_session_key(&mut self, pub_key: &BigUint, scram: &BigUint) {
            self.base.scrambler = scram.clone();
            let temp = &self.base.private_key + (&self.base.scrambler * &self.base.identity_hash);
            let subtraction = pub_key
                - &self
                    .base
                    .generator_g
                    .modpow(&self.base.identity_hash, &self.base.modulus_n)
                    * &self.base.multiplier_k;
            self.base.session_key = subtraction.modpow(&temp, &self.base.modulus_n);
        }

        pub fn get_public_key(&self) -> &BigUint {
            &self.base.public_key
        }

        pub fn get_private_key(&self) -> &BigUint {
            &self.base.private_key
        }

        pub fn get_session_key(&self) -> &BigUint {
            &self.base.session_key
        }

        pub fn get_identity_hash(&self) -> &BigUint {
            &self.base.identity_hash
        }
    }
}

fn main() {
    let modulus = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";

    println!("=== SRP6 Demo Started ===");

    let mut srp_server = srp::Server::new(
        "TEST",
        "test",
        modulus,
        3,
        2,
        128,
        256,
        256
    );

    let mut srp_client = srp::Client::new(
        "TEST",
        "test",
        modulus,
        3,
        2,
        srp_server.get_salt(),
        256
    );

    println!("Modulus = {}", srp_server.get_modulus());
    println!("Multiplier = {}", srp_server.get_multiplier());
    println!("Generator = {}", srp_server.get_generator());
    println!("Salt = {}", srp_server.get_salt());
    println!("IdentityHash = {}", srp_server.get_identity_hash());
    println!("Verifier = {}", srp_server.get_verifier());
    println!("Scrambler (u) = {}", srp_server.get_scrambler());
    println!();

    srp_server.compute_session_key(srp_client.get_public_key());
    srp_client.compute_session_key(srp_server.get_public_key(), srp_server.get_scrambler());

    println!("ServerPrivateKey (b) = {}", srp_server.get_private_key());
    println!("ServerPublicKey (B) = {}", srp_server.get_public_key());
    println!();
    println!("ClientPrivateKey (a) = {}", srp_client.get_private_key());
    println!("ClientPublicKey (A) = {}", srp_client.get_public_key());
    println!(
        "ClientIdentityHash (x) = {}",
        srp_client.get_identity_hash()
    );
    println!();
    println!("ServerSessionKey = {}", srp_server.get_session_key());
    println!("ClientSessionKey = {}", srp_client.get_session_key());
    println!();
    let passed = srp_server.get_session_key() == srp_client.get_session_key();
    println!(
        "Session keys{}match!",
        if passed { " " } else { " DO NOT " }
    );
}
