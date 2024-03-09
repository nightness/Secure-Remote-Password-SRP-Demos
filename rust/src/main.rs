extern crate sha2;
extern crate rand;
extern crate num_bigint;

mod srp {
    use num_traits::Zero;
    use num_bigint::{BigUint, RandBigInt};
    use sha2::{Digest, Sha256};
    use rand::thread_rng;

    struct Base {
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
        pub fn new() -> Base {
            Base {
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
    }

    pub struct Server {
        base: Base,
        pub modulus_n: BigUint,
        pub s_verifier: BigUint,
    }

    impl Server {
        pub fn new(
            user: &str,
            password: &str,
            modulus_n: &str,
            generator_g: u32,
            salt_bits: u16,
            scrambler_bits: u16,
        ) -> Server {
            let mut base = Base::new();
            let modulus_n = BigUint::parse_bytes(modulus_n.as_bytes(), 16).unwrap();
            base.generator_g = BigUint::from(generator_g);
            let mut rng = thread_rng();
            base.salt = rng.gen_biguint(salt_bits as u64);
            base.scrambler = rng.gen_biguint(scrambler_bits as u64);

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

            let mut rng = thread_rng();
            base.private_key = rng.gen_biguint(128);

            let public_key = &base
                .multiplier_k
                * &s_verifier +
                &base.generator_g.modpow(&base.private_key, &modulus_n);
            base.public_key = public_key;

            Server {
                base,
                modulus_n: modulus_n.clone(),
                s_verifier,
            }
        }

        pub fn set_session_key(&mut self, public_key: &BigUint) {
            let temp = public_key
                * &self.s_verifier.modpow(&self.base.scrambler, &self.modulus_n);
            self.base.session_key = temp.modpow(&self.base.private_key, &self.modulus_n);
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
    }

    pub struct Client {
        base: Base,
        modulus_n: BigUint,
    }

    impl Client {
        pub fn new(
            user: &str,
            password: &str,
            modulus_n: &str,
            generator_g: u32,
            salt: &BigUint,
        ) -> Client {
            let mut base = Base::new();
            let modulus_n = BigUint::parse_bytes(modulus_n.as_bytes(), 16).unwrap();
            base.generator_g = BigUint::from(generator_g);

            base.salt = salt.clone();
            base.session_key = BigUint::zero();
            
            let mut rng = thread_rng();
            base.private_key = rng.gen_biguint(128);

            let public_key = base.generator_g.modpow(&base.private_key, &modulus_n);
            base.public_key = public_key;

            let salt_hex = base.salt.to_str_radix(16);
            let hash_input = format!("{}{}:{}", salt_hex, user, password);
            let mut hasher = Sha256::new();
            hasher.update(hash_input.as_bytes());
            let hash_result = hasher.finalize();
            let identity_hash = BigUint::from_bytes_be(&hash_result);
            base.identity_hash = identity_hash;

            Client {
                base,
                modulus_n: modulus_n.clone(),
            }
        }

        pub fn set_session_key(&mut self, pub_key: &BigUint, scram: &BigUint) {
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

    let mut srp_server = srp::Server::new("TEST", "test", modulus, 2, 256, 128);
    let mut srp_client = srp::Client::new("TEST", "test", modulus, 2, srp_server.get_salt());

    srp_server.set_session_key(srp_client.get_public_key());
    srp_client.set_session_key(
        srp_server.get_public_key(),
        srp_server.get_scrambler(),
    );

    println!("=== SRP6 Demo Started ===");
    println!("Modulus = {}", srp_server.modulus_n);
    println!("Multiplier = {}", srp_server.get_multiplier());
    println!("Generator = {}", srp_server.get_generator());
    println!("Salt = {}", srp_server.get_salt());
    println!("IdentityHash = {}", srp_server.get_identity_hash());
    println!("Verifier = {}", srp_server.s_verifier);
    println!();
    println!("ServerPrivateKey (b) = {}", srp_server.get_private_key());
    println!("ServerPublicKey (B) = {}", srp_server.get_public_key());
    println!("Scrambler (u) = {}", srp_server.get_scrambler());
    println!();
    println!("ClientPrivateKey (a) = {}", srp_client.get_private_key());
    println!("ClientPublicKey (A)= {}", srp_client.get_public_key());
    println!("ClientIdentityHash (x) = {}", srp_client.get_identity_hash());
    println!();
    println!("ServerSessionKey = {}", srp_server.get_session_key());
    println!("ClientSessionKey = {}", srp_client.get_session_key());
    println!();
    let passed = srp_server.get_session_key() == srp_client.get_session_key();
    println!(
        "Test Results: {}",
        if passed { "PASSED!" } else { "FAILED!" }
    );
}
