import bigInt = require("big-integer");
export type IBigInteger = bigInt.BigInteger;

export class BigInt {
  static zero = BigInt.from(bigInt.zero);
  static one = BigInt.from(bigInt.one);

  private _value: IBigInteger;

  static from(
    value: bigInt.BigInteger | string | number,
    radix?: number
  ): BigInt {
    return new BigInt(value, radix);
  }

  static random(bitLength: number): BigInt {
    // Create a random binary string of bitLength
    let text = "";
    for (let index = 0; index < bitLength; index++)
      text += Math.random() >= 0.5 ? "0" : "1";
    return BigInt.from(text, 2);
  }

  private constructor(value: IBigInteger | string | number, radix?: number) {
    if (typeof value === "string") {
      this._value = bigInt(value, radix);
    } else if (typeof value === "number") {
      this._value = bigInt(value);
    } else {
      this._value = value;
    }
  }

  public add(other: BigInt): BigInt {
    return BigInt.from(this._value.add(other._value));
  }

  public subtract(other: BigInt): BigInt {
    return BigInt.from(this._value.subtract(other._value));
  }

  public multiply(other: BigInt): BigInt {
    return BigInt.from(this._value.multiply(other._value));
  }

  public divide(other: BigInt): BigInt {
    return BigInt.from(this._value.divide(other._value));
  }

  public mod(other: BigInt): BigInt {
    return BigInt.from(this._value.mod(other._value));
  }

  public modPow(exponent: BigInt, modulus: BigInt): BigInt {
    return BigInt.from(this._value.modPow(exponent._value, modulus._value));
  }

  public equals(other: BigInt): boolean {
    return this._value.equals(other._value);
  }

  public greater(other: BigInt): boolean {
    return this._value.greater(other._value);
  }

  public greaterOrEquals(other: BigInt): boolean {
    return this._value.greaterOrEquals(other._value);
  }

  public less(other: BigInt): boolean {
    return this._value.lesser(other._value);
  }

  public lessOrEquals(other: BigInt): boolean {
    return this._value.lesserOrEquals(other._value);
  }

  public isZero(): boolean {
    return this._value.isZero();
  }

  public isOne(): boolean {
    return this._value.equals(bigInt.one);
  }

  public isProbablePrime(): boolean {
    return this._value.isProbablePrime();
  }

  public isPrime(): boolean {
    return this._value.isPrime();
  }

  public toString(radix?: number): string {
    return this._value.toString(radix);
  }

  public valueOf(): number {
    return this._value.valueOf();
  }
}
