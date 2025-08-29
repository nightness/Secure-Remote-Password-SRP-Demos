/**
 * SHA3-256 implementation from scratch
 * Based on NIST FIPS 202 specification
 * Implements Keccak[512] with SHA3 padding
 */
public class SHA3Custom {
    private static final int ROUNDS = 24;
    private static final int RATE = 1088; // bits (136 bytes for SHA3-256)
    private static final int CAPACITY = 512; // bits
    private static final int OUTPUT_LENGTH = 256; // bits (32 bytes)
    
    // Keccak round constants
    private static final long[] ROUND_CONSTANTS = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    // Rho offsets for rotation
    private static final int[] RHO_OFFSETS = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    };

    private long[][] state;

    public SHA3Custom() {
        // Initialize 5x5 state matrix
        this.state = new long[5][5];
    }

    /**
     * Hash a message using SHA3-256
     */
    public static String hash(String message) {
        return hash(message.getBytes());
    }
    
    public static String hash(byte[] input) {
        SHA3Custom sha3 = new SHA3Custom();
        return sha3.digest(input);
    }

    /**
     * Main digest function
     */
    private String digest(byte[] input) {
        // Apply SHA3 padding (0x06)
        byte[] paddedInput = pad(input, (byte) 0x06);
        
        // Process input in rate-sized chunks
        int rateBytes = RATE / 8; // 136 bytes
        
        for (int i = 0; i < paddedInput.length; i += rateBytes) {
            byte[] chunk = new byte[rateBytes];
            System.arraycopy(paddedInput, i, chunk, 0, Math.min(rateBytes, paddedInput.length - i));
            absorb(chunk);
            keccakF();
        }

        // Squeeze phase - extract output
        return squeeze();
    }

    /**
     * SHA3 padding: message + 0x06 + 0x00...0x00 + 0x80
     */
    private byte[] pad(byte[] input, byte suffix) {
        int rateBytes = RATE / 8;
        int inputLen = input.length;
        int padLen = rateBytes - (inputLen % rateBytes);
        
        byte[] padded = new byte[inputLen + padLen];
        System.arraycopy(input, 0, padded, 0, inputLen);
        
        // Add suffix (0x06 for SHA3)
        padded[inputLen] = suffix;
        
        // Add 0x80 at the end
        padded[padded.length - 1] |= (byte) 0x80;
        
        return padded;
    }

    /**
     * Absorb phase - XOR input into state
     */
    private void absorb(byte[] chunk) {
        for (int i = 0; i < chunk.length; i += 8) {
            long lane = bytesToLane(chunk, i);
            int x = (i / 8) % 5;
            int y = (i / 8) / 5;
            if (y < 5) {
                state[y][x] ^= lane;
            }
        }
    }

    /**
     * Squeeze phase - extract output from state
     */
    private String squeeze() {
        int outputBytes = OUTPUT_LENGTH / 8; // 32 bytes
        byte[] output = new byte[outputBytes];
        
        int outputPos = 0;
        for (int y = 0; y < 5 && outputPos < outputBytes; y++) {
            for (int x = 0; x < 5 && outputPos < outputBytes; x++) {
                byte[] laneBytes = laneToBytes(state[y][x]);
                int bytesToCopy = Math.min(8, outputBytes - outputPos);
                System.arraycopy(laneBytes, 0, output, outputPos, bytesToCopy);
                outputPos += bytesToCopy;
            }
        }
        
        return bytesToHex(output);
    }

    /**
     * Keccak-f[1600] permutation
     */
    private void keccakF() {
        for (int round = 0; round < ROUNDS; round++) {
            theta();
            rhoPi();
            chi();
            iota(round);
        }
    }

    /**
     * Theta step
     */
    private void theta() {
        long[] C = new long[5];
        long[] D = new long[5];
        
        // Compute column parities
        for (int x = 0; x < 5; x++) {
            C[x] = state[0][x] ^ state[1][x] ^ state[2][x] ^ state[3][x] ^ state[4][x];
        }
        
        // Compute D values
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotateLeft(C[(x + 1) % 5], 1);
        }
        
        // Apply theta
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                state[y][x] ^= D[x];
            }
        }
    }

    /**
     * Rho and Pi steps combined
     */
    private void rhoPi() {
        long[][] newState = new long[5][5];
        
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int newX = y;
                int newY = (2 * x + 3 * y) % 5;
                int offset = RHO_OFFSETS[5 * y + x];
                newState[newY][newX] = rotateLeft(state[y][x], offset);
            }
        }
        
        state = newState;
    }

    /**
     * Chi step
     */
    private void chi() {
        long[][] newState = new long[5][5];
        
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                newState[y][x] = state[y][x] ^ 
                    ((~state[y][(x + 1) % 5]) & state[y][(x + 2) % 5]);
            }
        }
        
        state = newState;
    }

    /**
     * Iota step
     */
    private void iota(int round) {
        state[0][0] ^= ROUND_CONSTANTS[round];
    }

    /**
     * Rotate left (for 64-bit lanes)
     */
    private long rotateLeft(long value, int positions) {
        positions = positions % 64;
        return (value << positions) | (value >>> (64 - positions));
    }

    /**
     * Convert 8 bytes to lane (little-endian)
     */
    private long bytesToLane(byte[] bytes, int offset) {
        long lane = 0;
        for (int i = Math.min(8, bytes.length - offset) - 1; i >= 0; i--) {
            if (offset + i < bytes.length) {
                lane = (lane << 8) | (bytes[offset + i] & 0xFF);
            }
        }
        return lane;
    }

    /**
     * Convert lane to 8 bytes (little-endian)
     */
    private byte[] laneToBytes(long lane) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (lane & 0xFF);
            lane >>>= 8;
        }
        return bytes;
    }

    /**
     * Convert byte array to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b & 0xFF));
        }
        return hex.toString();
    }
}