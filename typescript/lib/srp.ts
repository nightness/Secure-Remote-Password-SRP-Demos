import { sha3 } from "./sha3";
import { assert } from "console";
import { BigInt } from "./BigInt";

class SecureRemotePasswordBase {
  // Common variables
  protected sessionKey = BigInt.zero;
  protected privateKey = BigInt.zero;
  protected publicKey = BigInt.zero;
  protected salt = BigInt.zero;
  protected multiplier_k = BigInt.zero;
  protected identityHash = BigInt.zero;
  protected generator_g = BigInt.zero;
  protected scrambler = BigInt.zero;

  constructor() {}

  public getPublicKey() {
    return this.publicKey;
  }

  public getPrivateKey() {
    return this.privateKey;
  }

  public getSessionKey() {
    return this.sessionKey;
  }

  public getSalt() {
    return this.salt;
  }

  public getMultiplier() {
    return this.multiplier_k;
  }

  public getIdentityHash() {
    return this.identityHash;
  }

  public getGenerator() {
    return this.generator_g;
  }

  public getScrambler() {
    return this.scrambler;
  }
}

export class SRP6Server extends SecureRemotePasswordBase {
  // Constructor initialized variables
  private modulus_N: BigInt;

  // Server calculated variables
  private sVerifier: BigInt;

  // Server Constructor
  constructor(
    user: string,
    password: string,
    modulus_N: string,
    generator_g: number,
    saltBits: number,
    scramblerBits: number
  ) {
    super();
    this.multiplier_k = BigInt.from("3"); //SRP6 constant
    this.modulus_N = BigInt.from(modulus_N, 16);
    this.generator_g = BigInt.from(generator_g);
    this.salt = BigInt.random(saltBits);
    this.scrambler = BigInt.random(scramblerBits);

    assert(this.scrambler.greater(BigInt.zero), "scrambler invalid");
    assert(this.multiplier_k.greater(BigInt.zero), "multiplier_k invalid");
    assert(this.generator_g.greater(BigInt.zero), "generator_g invalid");
    assert(this.modulus_N.greater(BigInt.zero), "modulus_N invalid");
    assert(this.salt.greater(BigInt.zero), "salt invalid");

    // Server-side variables
    const hash = sha3(`${this.salt.toString(16)}${user}:${password}`);
    this.identityHash = BigInt.from(hash, 16);
    this.sVerifier = this.generator_g.modPow(this.identityHash, this.modulus_N);

    // Keys
    this.privateKey = BigInt.random(256);

    // kv + g^b   (mod N)
    this.publicKey = this.multiplier_k
      .multiply(this.sVerifier)
      .add(this.generator_g.modPow(this.privateKey, this.modulus_N));
  }

  public setSessionKey(publicKey: BigInt) {
    this.sessionKey = publicKey
      .multiply(this.sVerifier.modPow(this.scrambler, this.modulus_N))
      .modPow(this.privateKey, this.modulus_N);
  }

  public getIdentityHash() {
    return this.identityHash;
  }

  public getModulus() {
    return this.modulus_N;
  }

  public getVerifier() {
    return this.sVerifier;
  }
}

export class SRP6Client extends SecureRemotePasswordBase {
  // Constructor initialized variables
  private modulus_N: BigInt;

  // Client Constructor
  constructor(
    user: string,
    password: string,
    modulus_N: string,
    generator_g: number,
    salt: BigInt
  ) {
    super();
    this.multiplier_k = BigInt.from("3"); //SRP6 constant
    this.modulus_N = BigInt.from(modulus_N, 16);
    this.generator_g = BigInt.from(generator_g);
    this.salt = salt;
    this.sessionKey = BigInt.zero;

    assert(this.multiplier_k.greater(BigInt.zero), "multiplier_k invalid");
    assert(this.generator_g.greater(BigInt.zero), "generator_g invalid");
    assert(this.modulus_N.greater(BigInt.zero), "modulus_N invalid");
    assert(this.salt.greater(BigInt.zero), "salt invalid");

    this.privateKey = BigInt.random(128);
    // g^a   (mod N)
    this.publicKey = this.generator_g.modPow(this.privateKey, this.modulus_N);

    // Identity Hash
    const hash = sha3(`${this.salt.toString(16)}${user}:${password}`);
    this.identityHash = BigInt.from(hash, 16);
  }

  public setSessionKey(pubKey: BigInt, scram: BigInt) {
    this.scrambler = scram;
    const temp = this.privateKey.add(
      this.scrambler.multiply(this.identityHash)
    );
    this.sessionKey = pubKey
      .subtract(
        this.generator_g
          .modPow(this.identityHash, this.modulus_N)
          .multiply(this.multiplier_k)
      )
      .modPow(temp, this.modulus_N);
  }
}
