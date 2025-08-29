/**
 * SHA3-256 implementation from scratch
 * Based on NIST FIPS 202 specification
 * Implements Keccak[512] with SHA3 padding
 */

pub struct SHA3_256 {
    state: [[u64; 5]; 5],
}

const ROUNDS: usize = 24;
const RATE: usize = 1088; // bits (136 bytes for SHA3-256)
const OUTPUT_LENGTH: usize = 256; // bits (32 bytes)

// Keccak round constants
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// Rho offsets for rotation
const RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

impl SHA3_256 {
    pub fn new() -> Self {
        SHA3_256 {
            state: [[0; 5]; 5],
        }
    }

    /// Hash a message using SHA3-256
    pub fn hash(message: &[u8]) -> String {
        let mut sha3 = SHA3_256::new();
        sha3.digest(message)
    }

    /// Hash a string message
    pub fn hash_string(message: &str) -> String {
        SHA3_256::hash(message.as_bytes())
    }

    /// Main digest function
    fn digest(&mut self, input: &[u8]) -> String {
        // Apply SHA3 padding (0x06)
        let padded_input = self.pad(input, 0x06);
        
        // Process input in rate-sized chunks
        let rate_bytes = RATE / 8; // 136 bytes
        
        for chunk in padded_input.chunks(rate_bytes) {
            self.absorb(chunk);
            self.keccak_f();
        }

        // Squeeze phase - extract output
        self.squeeze()
    }

    /// SHA3 padding: message + 0x06 + 0x00...0x00 + 0x80
    fn pad(&self, input: &[u8], suffix: u8) -> Vec<u8> {
        let rate_bytes = RATE / 8;
        let input_len = input.len();
        let pad_len = rate_bytes - (input_len % rate_bytes);
        
        let mut padded = Vec::with_capacity(input_len + pad_len);
        padded.extend_from_slice(input);
        
        // Add suffix (0x06 for SHA3)
        padded.push(suffix);
        
        // Add zeros
        for _ in 1..pad_len {
            padded.push(0);
        }
        
        // Add 0x80 at the end
        if padded.len() > 0 {
            *padded.last_mut().unwrap() |= 0x80;
        }
        
        padded
    }

    /// Absorb phase - XOR input into state
    fn absorb(&mut self, chunk: &[u8]) {
        for (i, chunk_8) in chunk.chunks(8).enumerate() {
            let lane = self.bytes_to_lane(chunk_8);
            let x = i % 5;
            let y = i / 5;
            if y < 5 {
                self.state[y][x] ^= lane;
            }
        }
    }

    /// Squeeze phase - extract output from state
    fn squeeze(&self) -> String {
        let output_bytes = OUTPUT_LENGTH / 8; // 32 bytes
        let mut output = Vec::with_capacity(output_bytes);
        
        let mut output_pos = 0;
        for y in 0..5 {
            if output_pos >= output_bytes { break; }
            for x in 0..5 {
                if output_pos >= output_bytes { break; }
                let lane_bytes = self.lane_to_bytes(self.state[y][x]);
                let bytes_to_copy = std::cmp::min(8, output_bytes - output_pos);
                output.extend_from_slice(&lane_bytes[..bytes_to_copy]);
                output_pos += bytes_to_copy;
            }
        }
        
        output.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Keccak-f[1600] permutation
    fn keccak_f(&mut self) {
        for round in 0..ROUNDS {
            self.theta();
            self.rho_pi();
            self.chi();
            self.iota(round);
        }
    }

    /// Theta step
    fn theta(&mut self) {
        let mut c = [0u64; 5];
        let mut d = [0u64; 5];
        
        // Compute column parities
        for x in 0..5 {
            c[x] = self.state[0][x] ^ self.state[1][x] ^ self.state[2][x] ^ self.state[3][x] ^ self.state[4][x];
        }
        
        // Compute D values
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ self.rotate_left(c[(x + 1) % 5], 1);
        }
        
        // Apply theta
        for y in 0..5 {
            for x in 0..5 {
                self.state[y][x] ^= d[x];
            }
        }
    }

    /// Rho and Pi steps combined
    fn rho_pi(&mut self) {
        let mut new_state = [[0u64; 5]; 5];
        
        for y in 0..5 {
            for x in 0..5 {
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                let offset = RHO_OFFSETS[5 * y + x];
                new_state[new_y][new_x] = self.rotate_left(self.state[y][x], offset);
            }
        }
        
        self.state = new_state;
    }

    /// Chi step
    fn chi(&mut self) {
        let mut new_state = [[0u64; 5]; 5];
        
        for y in 0..5 {
            for x in 0..5 {
                new_state[y][x] = self.state[y][x] ^ 
                    ((!self.state[y][(x + 1) % 5]) & self.state[y][(x + 2) % 5]);
            }
        }
        
        self.state = new_state;
    }

    /// Iota step
    fn iota(&mut self, round: usize) {
        self.state[0][0] ^= ROUND_CONSTANTS[round];
    }

    /// Rotate left (for 64-bit lanes)
    fn rotate_left(&self, value: u64, positions: u32) -> u64 {
        let positions = positions % 64;
        if positions == 0 {
            value
        } else {
            (value << positions) | (value >> (64 - positions))
        }
    }

    /// Convert bytes to lane (little-endian)
    fn bytes_to_lane(&self, bytes: &[u8]) -> u64 {
        let mut lane = 0u64;
        let len = bytes.len().min(8);
        for i in 0..len {
            lane |= (bytes[i] as u64) << (8 * i);
        }
        lane
    }

    /// Convert lane to bytes (little-endian)
    fn lane_to_bytes(&self, lane: u64) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        let mut temp_lane = lane;
        for i in 0..8 {
            bytes[i] = (temp_lane & 0xFF) as u8;
            temp_lane >>= 8;
        }
        bytes
    }
}