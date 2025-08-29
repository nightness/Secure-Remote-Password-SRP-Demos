using System;
using System.Text;

namespace SRP6
{
    /// <summary>
    /// SHA3-256 implementation from scratch
    /// Based on NIST FIPS 202 specification
    /// Implements Keccak[512] with SHA3 padding
    /// </summary>
    public class SHA3Custom
    {
        private const int ROUNDS = 24;
        private const int RATE = 1088; // bits (136 bytes for SHA3-256)
        private const int CAPACITY = 512; // bits
        private const int OUTPUT_LENGTH = 256; // bits (32 bytes)
        
        // Keccak round constants
        private static readonly ulong[] ROUND_CONSTANTS = {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        // Rho offsets for rotation
        private static readonly int[] RHO_OFFSETS = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        };

        private ulong[,] state;

        public SHA3Custom()
        {
            // Initialize 5x5 state matrix
            state = new ulong[5, 5];
        }

        /// <summary>
        /// Hash a message using SHA3-256
        /// </summary>
        public static string Hash(string message)
        {
            return Hash(Encoding.UTF8.GetBytes(message));
        }

        public static string Hash(byte[] input)
        {
            var sha3 = new SHA3Custom();
            return sha3.Digest(input);
        }

        /// <summary>
        /// Main digest function
        /// </summary>
        private string Digest(byte[] input)
        {
            // Apply SHA3 padding (0x06)
            byte[] paddedInput = Pad(input, 0x06);
            
            // Process input in rate-sized chunks
            int rateBytes = RATE / 8; // 136 bytes
            
            for (int i = 0; i < paddedInput.Length; i += rateBytes)
            {
                byte[] chunk = new byte[rateBytes];
                Array.Copy(paddedInput, i, chunk, 0, Math.Min(rateBytes, paddedInput.Length - i));
                Absorb(chunk);
                KeccakF();
            }

            // Squeeze phase - extract output
            return Squeeze();
        }

        /// <summary>
        /// SHA3 padding: message + 0x06 + 0x00...0x00 + 0x80
        /// </summary>
        private byte[] Pad(byte[] input, byte suffix)
        {
            int rateBytes = RATE / 8;
            int inputLen = input.Length;
            int padLen = rateBytes - (inputLen % rateBytes);
            
            byte[] padded = new byte[inputLen + padLen];
            Array.Copy(input, 0, padded, 0, inputLen);
            
            // Add suffix (0x06 for SHA3)
            padded[inputLen] = suffix;
            
            // Add 0x80 at the end
            padded[padded.Length - 1] |= 0x80;
            
            return padded;
        }

        /// <summary>
        /// Absorb phase - XOR input into state
        /// </summary>
        private void Absorb(byte[] chunk)
        {
            for (int i = 0; i < chunk.Length; i += 8)
            {
                ulong lane = BytesToLane(chunk, i);
                int x = (i / 8) % 5;
                int y = (i / 8) / 5;
                if (y < 5)
                {
                    state[y, x] ^= lane;
                }
            }
        }

        /// <summary>
        /// Squeeze phase - extract output from state
        /// </summary>
        private string Squeeze()
        {
            int outputBytes = OUTPUT_LENGTH / 8; // 32 bytes
            byte[] output = new byte[outputBytes];
            
            int outputPos = 0;
            for (int y = 0; y < 5 && outputPos < outputBytes; y++)
            {
                for (int x = 0; x < 5 && outputPos < outputBytes; x++)
                {
                    byte[] laneBytes = LaneToBytes(state[y, x]);
                    int bytesToCopy = Math.Min(8, outputBytes - outputPos);
                    Array.Copy(laneBytes, 0, output, outputPos, bytesToCopy);
                    outputPos += bytesToCopy;
                }
            }
            
            return BytesToHex(output);
        }

        /// <summary>
        /// Keccak-f[1600] permutation
        /// </summary>
        private void KeccakF()
        {
            for (int round = 0; round < ROUNDS; round++)
            {
                Theta();
                RhoPi();
                Chi();
                Iota(round);
            }
        }

        /// <summary>
        /// Theta step
        /// </summary>
        private void Theta()
        {
            ulong[] C = new ulong[5];
            ulong[] D = new ulong[5];
            
            // Compute column parities
            for (int x = 0; x < 5; x++)
            {
                C[x] = state[0, x] ^ state[1, x] ^ state[2, x] ^ state[3, x] ^ state[4, x];
            }
            
            // Compute D values
            for (int x = 0; x < 5; x++)
            {
                D[x] = C[(x + 4) % 5] ^ RotateLeft(C[(x + 1) % 5], 1);
            }
            
            // Apply theta
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    state[y, x] ^= D[x];
                }
            }
        }

        /// <summary>
        /// Rho and Pi steps combined
        /// </summary>
        private void RhoPi()
        {
            ulong[,] newState = new ulong[5, 5];
            
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    int newX = y;
                    int newY = (2 * x + 3 * y) % 5;
                    int offset = RHO_OFFSETS[5 * y + x];
                    newState[newY, newX] = RotateLeft(state[y, x], offset);
                }
            }
            
            state = newState;
        }

        /// <summary>
        /// Chi step
        /// </summary>
        private void Chi()
        {
            ulong[,] newState = new ulong[5, 5];
            
            for (int y = 0; y < 5; y++)
            {
                for (int x = 0; x < 5; x++)
                {
                    newState[y, x] = state[y, x] ^ 
                        ((~state[y, (x + 1) % 5]) & state[y, (x + 2) % 5]);
                }
            }
            
            state = newState;
        }

        /// <summary>
        /// Iota step
        /// </summary>
        private void Iota(int round)
        {
            state[0, 0] ^= ROUND_CONSTANTS[round];
        }

        /// <summary>
        /// Rotate left (for 64-bit lanes)
        /// </summary>
        private ulong RotateLeft(ulong value, int positions)
        {
            positions = positions % 64;
            return (value << positions) | (value >> (64 - positions));
        }

        /// <summary>
        /// Convert 8 bytes to lane (little-endian)
        /// </summary>
        private ulong BytesToLane(byte[] bytes, int offset)
        {
            ulong lane = 0;
            for (int i = Math.Min(8, bytes.Length - offset) - 1; i >= 0; i--)
            {
                if (offset + i < bytes.Length)
                {
                    lane = (lane << 8) | bytes[offset + i];
                }
            }
            return lane;
        }

        /// <summary>
        /// Convert lane to 8 bytes (little-endian)
        /// </summary>
        private byte[] LaneToBytes(ulong lane)
        {
            byte[] bytes = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                bytes[i] = (byte)(lane & 0xFF);
                lane >>= 8;
            }
            return bytes;
        }

        /// <summary>
        /// Convert byte array to hex string
        /// </summary>
        private string BytesToHex(byte[] bytes)
        {
            var hex = new StringBuilder();
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
    }
}