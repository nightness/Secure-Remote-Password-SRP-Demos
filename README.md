# Secure Remote Password Protocol Implementation

This repository contains an implementation of the Secure Remote Password (SRP) protocol in four different programming languages: C#, Java, Rust, and TypeScript. The SRP protocol is a cryptographic protocol that provides password-based authentication without sending the password over the network, enhancing security.

## 🔒 Custom SHA3-256 Implementation

**Latest Major Update:** All implementations now feature **custom SHA3-256 implementations built from scratch** based on the NIST FIPS 202 specification. No external cryptographic libraries are used for the SHA3 functionality.

### 🎯 Custom Implementation Features:
- **Pure Implementation**: Complete Keccak-f[1600] permutation implemented from scratch
- **NIST FIPS 202 Compliant**: Follows the official SHA3 standard specification exactly
- **Fully Tested**: All implementations pass official NIST test vectors
- **Educational Value**: Shows the complete SHA3 algorithm implementation in each language
- **Production Ready**: Optimized and validated against known test vectors

### 🧪 Validation Results:
All implementations pass the complete NIST SHA3-256 test suite:
- ✅ Empty string test
- ✅ Short ASCII input test  
- ✅ Longer ASCII input test
- ✅ 1 million character stress test

### Security Benefits:
- **Enhanced Security**: SHA3-256 provides stronger resistance against collision attacks
- **Future-Proof**: Based on the Keccak algorithm, offering different cryptographic properties than SHA-2
- **No Dependencies**: Custom implementation eliminates external crypto library dependencies
- **Transparent**: Full algorithm visibility for security auditing
- **Consistent**: All four language implementations produce identical results

## Prerequisites

Before running the implementations, make sure you have the following installed:

- **C#**: .NET 9.0 SDK or later
- **Java**: JDK 8 or later 
- **Rust**: Rust toolchain (rustc and cargo)
- **TypeScript**: Node.js 18+ and npm

### Dependencies:
- **TypeScript**: `big-integer` for large number operations
- **Java**: No external dependencies (pure Java implementation)
- **Rust**: `num-bigint`, `num-traits`, `rand` for big integers and random generation
- **C#**: No external dependencies (pure .NET implementation)

**Note**: All SHA3-256 implementations are custom-built from scratch with no external crypto dependencies!

## Running the Implementations

### C#

Navigate to the `csharp` directory:

```bash
cd csharp
```

**Run SRP Demo:**
```bash
dotnet run
```

**Test SHA3-256 Implementation:**
```bash
dotnet run sha3test
```

The C# implementation features a complete custom SHA3-256 implementation and includes clean, modern .NET practices with proper error handling.

### Java

Navigate to the `java` directory:

```bash
cd java
```

**Compile all files:**
```bash
javac *.java
```

**Run SRP Demo:**
```bash
java SRP6
```

**Test SHA3-256 Implementation:**
```bash
java SHA3Test
```

The Java implementation features a complete custom SHA3-256 implementation with no external dependencies.

### Rust

Navigate to the `rust` directory:

```bash
cd rust
```

**Run SRP Demo:**
```bash
cargo run
```

The Rust implementation features a complete custom SHA3-256 implementation. Dependencies are automatically managed by Cargo and include only big integer support.

### TypeScript

Navigate to the `typescript` directory:

```bash
cd typescript
```

**Install dependencies:**
```bash
npm install
```

**Run SRP Demo:**
```bash
npm test
```

**Test SHA3-256 Implementation:**
```bash
npm run test-sha3
```

**Build Only:**
```bash
npm run build
```

The TypeScript implementation features a complete custom SHA3-256 implementation built with BigInt support for 64-bit operations.

## 🔧 Implementation Details

### SHA3-256 Algorithm Components

Each language implementation includes:

1. **Keccak-f[1600] Permutation Function**:
   - **θ (Theta)**: Column parity computation and XOR
   - **ρ (Rho)**: Bitwise rotation of lanes  
   - **π (Pi)**: Lane position permutation
   - **χ (Chi)**: Nonlinear transformation step
   - **ι (Iota)**: Round constant addition

2. **SHA3-256 Specific Features**:
   - **Rate**: 1088 bits (136 bytes)
   - **Capacity**: 512 bits  
   - **Output Length**: 256 bits (32 bytes)
   - **Padding**: SHA3 padding rule (0x06 + 0x80)
   - **Rounds**: 24 Keccak-f rounds

3. **Key Files Per Language**:

| Language   | Core Implementation | Test Vectors | SRP Integration |
|------------|-------------------|--------------|----------------|
| TypeScript | `sha3-custom.ts`  | `sha3-test.ts` | `sha3.ts` |
| Java       | `SHA3Custom.java` | `SHA3Test.java` | `SHA3Util.java` |
| Rust       | `sha3_custom.rs`  | `sha3_test.rs` | `main.rs` |
| C#         | `SHA3Custom.cs`   | `SHA3Test.cs` | `Sha3Extensions.cs` |

### Performance Characteristics

- **Small inputs**: < 5ms across all implementations
- **Large inputs (1M chars)**: 100-1600ms depending on language
- **Memory efficient**: Fixed 200-byte state matrix
- **No heap allocations**: During hash computation (language dependent)

## 🧪 Testing

All implementations are validated against official NIST test vectors:

1. **Empty String Test**
   - Input: `""`
   - Expected: `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`

2. **Short ASCII Test**  
   - Input: `"abc"`
   - Expected: `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532`

3. **Medium ASCII Test**
   - Input: `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`
   - Expected: `41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376`

4. **Stress Test**
   - Input: 1,000,000 'a' characters
   - Expected: `5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1`

## Contributing

Contributions are welcome! If you have any improvements or bug fixes, please feel free to fork the repository and submit a pull request.

## License

This project is licensed under the [MIT License](./LICENSE). Feel free to use, modify, and distribute the code as you see fit.

## Acknowledgements

This project was created to provide a practical implementation of the Secure Remote Password protocol in multiple programming languages for educational and demonstration purposes. I hope it serves as a useful resource for those interested in cryptographic protocols and security.
