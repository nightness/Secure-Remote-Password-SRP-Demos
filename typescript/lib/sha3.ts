export function sha3(input: string): string {
    return SHA3_256.hash(input);
}

/**
 * SHA3-256 implementation from scratch
 * Based on NIST FIPS 202 specification
 * Implements Keccak[512] with SHA3 padding
 */

export class SHA3_256 {
    private static readonly ROUNDS = 24;
    private static readonly RATE = 1088; // bits (136 bytes for SHA3-256)
    private static readonly CAPACITY = 512; // bits
    private static readonly OUTPUT_LENGTH = 256; // bits (32 bytes)
    
    // Keccak round constants
    private static readonly ROUND_CONSTANTS = [
        0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
        0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
        0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
        0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
        0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
        0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
    ];

    // Rho offsets for rotation
    private static readonly RHO_OFFSETS = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    ];

    private state: bigint[][];

    constructor() {
        // Initialize 5x5 state matrix
        this.state = Array(5).fill(null).map(() => Array(5).fill(0n));
    }

    /**
     * Hash a message using SHA3-256
     */
    public static hash(message: string | Uint8Array): string {
        const sha3 = new SHA3_256();
        const input = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        return sha3.digest(input);
    }

    /**
     * Main digest function
     */
    private digest(input: Uint8Array): string {
        // Apply SHA3 padding (0x06)
        const paddedInput = this.pad(input, 0x06);
        
        // Process input in rate-sized chunks
        const rateBytes = SHA3_256.RATE / 8; // 136 bytes
        
        for (let i = 0; i < paddedInput.length; i += rateBytes) {
            const chunk = paddedInput.slice(i, i + rateBytes);
            this.absorb(chunk);
            this.keccakF();
        }

        // Squeeze phase - extract output
        return this.squeeze();
    }

    /**
     * SHA3 padding: message + 0x06 + 0x00...0x00 + 0x80
     */
    private pad(input: Uint8Array, suffix: number): Uint8Array {
        const rateBytes = SHA3_256.RATE / 8;
        const inputLen = input.length;
        const padLen = rateBytes - (inputLen % rateBytes);
        
        const padded = new Uint8Array(inputLen + padLen);
        padded.set(input, 0);
        
        // Add suffix (0x06 for SHA3)
        padded[inputLen] = suffix;
        
        // Add 0x80 at the end
        padded[padded.length - 1] |= 0x80;
        
        return padded;
    }

    /**
     * Absorb phase - XOR input into state
     */
    private absorb(chunk: Uint8Array): void {
        for (let i = 0; i < chunk.length; i += 8) {
            const lane = this.bytesToLane(chunk.slice(i, i + 8));
            const x = Math.floor(i / 8) % 5;
            const y = Math.floor(i / 40);
            if (y < 5) {
                this.state[y][x] ^= lane;
            }
        }
    }

    /**
     * Squeeze phase - extract output from state
     */
    private squeeze(): string {
        const outputBytes = SHA3_256.OUTPUT_LENGTH / 8; // 32 bytes
        const output = new Uint8Array(outputBytes);
        
        let outputPos = 0;
        for (let y = 0; y < 5 && outputPos < outputBytes; y++) {
            for (let x = 0; x < 5 && outputPos < outputBytes; x++) {
                const laneBytes = this.laneToBytes(this.state[y][x]);
                const bytesToCopy = Math.min(8, outputBytes - outputPos);
                output.set(laneBytes.slice(0, bytesToCopy), outputPos);
                outputPos += bytesToCopy;
            }
        }
        
        return Array.from(output).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Keccak-f[1600] permutation
     */
    private keccakF(): void {
        for (let round = 0; round < SHA3_256.ROUNDS; round++) {
            this.theta();
            this.rhoPi();
            this.chi();
            this.iota(round);
        }
    }

    /**
     * Theta step
     */
    private theta(): void {
        const C = new Array(5).fill(0n);
        const D = new Array(5).fill(0n);
        
        // Compute column parities
        for (let x = 0; x < 5; x++) {
            C[x] = this.state[0][x] ^ this.state[1][x] ^ this.state[2][x] ^ this.state[3][x] ^ this.state[4][x];
        }
        
        // Compute D values
        for (let x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ this.rotateLeft(C[(x + 1) % 5], 1);
        }
        
        // Apply theta
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                this.state[y][x] ^= D[x];
            }
        }
    }

    /**
     * Rho and Pi steps combined
     */
    private rhoPi(): void {
        const newState = Array(5).fill(null).map(() => Array(5).fill(0n));
        
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                const newX = y;
                const newY = (2 * x + 3 * y) % 5;
                const offset = SHA3_256.RHO_OFFSETS[5 * y + x];
                newState[newY][newX] = this.rotateLeft(this.state[y][x], offset);
            }
        }
        
        this.state = newState;
    }

    /**
     * Chi step
     */
    private chi(): void {
        const newState = Array(5).fill(null).map(() => Array(5).fill(0n));
        
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                newState[y][x] = this.state[y][x] ^ 
                    ((~this.state[y][(x + 1) % 5]) & this.state[y][(x + 2) % 5]);
            }
        }
        
        this.state = newState;
    }

    /**
     * Iota step
     */
    private iota(round: number): void {
        this.state[0][0] ^= SHA3_256.ROUND_CONSTANTS[round];
    }

    /**
     * Rotate left (for 64-bit lanes)
     */
    private rotateLeft(value: bigint, positions: number): bigint {
        positions = positions % 64;
        return ((value << BigInt(positions)) & 0xFFFFFFFFFFFFFFFFn) | 
               ((value & 0xFFFFFFFFFFFFFFFFn) >> BigInt(64 - positions));
    }

    /**
     * Convert 8 bytes to lane (little-endian)
     */
    private bytesToLane(bytes: Uint8Array): bigint {
        let lane = 0n;
        for (let i = Math.min(bytes.length, 8) - 1; i >= 0; i--) {
            lane = (lane << 8n) | BigInt(bytes[i]);
        }
        return lane;
    }

    /**
     * Convert lane to 8 bytes (little-endian)
     */
    private laneToBytes(lane: bigint): Uint8Array {
        const bytes = new Uint8Array(8);
        for (let i = 0; i < 8; i++) {
            bytes[i] = Number(lane & 0xFFn);
            lane >>= 8n;
        }
        return bytes;
    }
}