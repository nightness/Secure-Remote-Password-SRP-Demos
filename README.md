# Secure Remote Password Protocol Implementation

This repository contains an implementation of the Secure Remote Password (SRP) protocol in four different programming languages: C#, Java, Rust, and TypeScript. The SRP protocol is a cryptographic protocol that provides password-based authentication without sending the password over the network, enhancing security.

## Prerequisites

Before running the implementations, make sure you have the following installed:

- For C#: .NET SDK
- For Java: JDK and a compatible IDE like IntelliJ IDEA or Eclipse
- For Rust: Rust toolchain (rustc and cargo)
- For TypeScript: Node.js and npm

## Running the Implementations

### C#

Navigate to the `csharp` directory:

```bash
cd csharp
```

Build and run the program using the .NET CLI:

```bash
dotnet build
dotnet run
```

### Java

Navigate to the `java` directory:

```bash
cd java
```

Compile and run the Java file. If you are using an IDE like IntelliJ IDEA or Eclipse, you can import the project and run it directly from the IDE. Otherwise, use the following commands:

```bash
javac SRP6.java
java SRP6
```

### Rust

Navigate to the `rust` directory:

```bash
cd rust
```

Build and run the program using Cargo:

```bash
cargo build
cargo run
```

### TypeScript

Navigate to the `typescript` directory:

```bash
cd typescript
```

Install the dependencies:

```bash
npm install
```

Compile the TypeScript files to JavaScript:

```bash
npm run test
```

## Contributing

Contributions are welcome! If you have any improvements or bug fixes, please feel free to fork the repository and submit a pull request.

## License

This project is licensed under the [MIT License](./LICENSE). Feel free to use, modify, and distribute the code as you see fit.

## Acknowledgements

This project was created to provide a practical implementation of the Secure Remote Password protocol in multiple programming languages for educational and demonstration purposes. I hope it serves as a useful resource for those interested in cryptographic protocols and security.
