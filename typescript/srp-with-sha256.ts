import { sha256 as sha } from 'js-sha256'
//import { sha512 as sha } from 'js-sha512'
import bigInt = require('big-integer')
import { BigInteger } from 'big-integer'
import { assert } from 'console';

function newRandomBigInt(bitLength: number) {
    let text = ''
    for (let index = 0; index < bitLength; index++)
        text += Math.random() >= 0.5 ? '0' : '1'
    return bigInt(text, 2)
}

class SecureRemotePasswordBase {
    // Common variables
    protected sessionKey = bigInt.zero
    protected privateKey = bigInt.zero
    protected publicKey = bigInt.zero
    protected salt = bigInt.zero
    protected multiplier_k = bigInt.zero
    protected identityHash = bigInt.zero
    protected generator_g = bigInt.zero
    protected scrambler = bigInt.zero

    constructor() {}

    public getPublicKey() {
        return this.publicKey
    }

    public getPrivateKey() {
        return this.privateKey
    }

    public getSessionKey() {
        return this.sessionKey
    }

    public getSalt() {
        return this.salt
    }

    public getMultiplier() {
        return this.multiplier_k
    }

    public getIdentityHash() {
        return this.identityHash
    }

    public getGenerator() {
        return this.generator_g
    }

    public getScrambler() {
        return this.scrambler
    }
}

class SRP6Server extends SecureRemotePasswordBase {
    // Constructor initialized variables
    private modulus_N: BigInteger

    // Server calculated variables
    private sVerifier: BigInteger

    // Server Constructor
    constructor(
        user: string,
        password: string,
        modulus_N: string,
        generator_g: number,
        saltBits: number,
        scramblerBits: number
    ) {
        super()
        this.multiplier_k = bigInt('3') //SRP6 constant
        this.modulus_N = bigInt(modulus_N, 16)
        this.generator_g = bigInt(generator_g)
        this.salt = newRandomBigInt(saltBits)
        this.scrambler = newRandomBigInt(scramblerBits)

        assert(this.scrambler > bigInt.zero, 'scrambler invalid')
        assert(this.multiplier_k > bigInt.zero, 'multiplier_k invalid')
        assert(this.generator_g > bigInt.zero, 'generator_g invalid')
        assert(this.modulus_N > bigInt.zero, 'modulus_N invalid')
        assert(this.salt > bigInt.zero, 'salt invalid')

        // Server-side variables
        const hash = sha(`${this.salt.toString(16)}${user}:${password}`)
        this.identityHash = bigInt(hash, 16)
        this.sVerifier = this.generator_g.modPow(this.identityHash, this.modulus_N)

        // Keys
        this.privateKey = newRandomBigInt(256)

        // kv + g^b   (mod N)
        this.publicKey = this.multiplier_k
            .multiply(this.sVerifier)
            .add(this.generator_g.modPow(this.privateKey, this.modulus_N))
    }

    public setSessionKey(publicKey: BigInteger) {
        this.sessionKey = publicKey
            .multiply(this.sVerifier.modPow(this.scrambler, this.modulus_N))
            .modPow(this.privateKey, this.modulus_N)
    }

    public getIdentityHash() {
        return this.identityHash
    }

    public getModulus() {
        return this.modulus_N
    }

    public getVerifier() {
        return this.sVerifier
    }
}

class SRP6Client extends SecureRemotePasswordBase {
    // Constructor initialized variables
    private modulus_N: BigInteger

    // Client Constructor
    constructor(
        user: string,
        password: string,
        modulus_N: string,
        generator_g: number,
        salt: BigInteger
    ) {
        super()
        this.multiplier_k = bigInt('3') //SRP6 constant
        this.modulus_N = bigInt(modulus_N, 16)
        this.generator_g = bigInt(generator_g)
        this.salt = salt
        this.sessionKey = bigInt.zero

        assert(this.multiplier_k > bigInt.zero, 'multiplier_k invalid')
        assert(this.generator_g > bigInt.zero, 'generator_g invalid')
        assert(this.modulus_N > bigInt.zero, 'modulus_N invalid')
        assert(this.salt > bigInt.zero, 'salt invalid')


        this.privateKey = newRandomBigInt(128)
        // g^a   (mod N)
        this.publicKey = this.generator_g.modPow(this.privateKey, this.modulus_N)

        // Identity Hash
        const hash = sha(`${this.salt.toString(16)}${user}:${password}`)
        this.identityHash = bigInt(hash, 16)
    }

    public setSessionKey(pubKey: BigInteger, scram: BigInteger) {
        this.publicKey = pubKey
        this.scrambler = scram
        const temp = this.privateKey.add(this.scrambler.multiply(this.identityHash))
        this.sessionKey = pubKey
            .subtract(
                this.generator_g
                    .modPow(this.identityHash, this.modulus_N)
                    .multiply(this.multiplier_k)
            )
            .modPow(temp, this.modulus_N)
    }
}

// Must be a prime number
const modulus = '115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3'

const srpServer = new SRP6Server('TEST', 'test', modulus, 420, 256, 128)
const srpClient = new SRP6Client('TEST', 'test', modulus, 420, srpServer.getSalt())

// This is the information that would normally be exchanged over the network connection
srpServer.setSessionKey(srpClient.getPublicKey())
srpClient.setSessionKey(srpServer.getPublicKey(), srpServer.getScrambler())


console.log('=== SRP6 Demo Started ===')
console.log('Modulus =', srpServer.getModulus())
console.log('Multiplier =', srpServer.getMultiplier())
console.log('Generator= ', srpServer.getGenerator())
console.log('Salt =', srpServer.getSalt())
console.log('IdentityHash =', srpServer.getIdentityHash())
console.log('Verifier =', srpServer.getVerifier())
console.log('')
console.log('ServerPrivateKey (b) =', srpServer.getPrivateKey())
console.log('ServerPublicKey (B) = ', srpServer.getPublicKey())
console.log('Scrambler (u)=', srpServer.getScrambler())
console.log('')
console.log('ClientPrivateKey (a) =', srpClient.getPrivateKey())
console.log('ClientPublicKey (A)=', srpClient.getPublicKey())
console.log('ClientIdentityHash (x) =', srpClient.getIdentityHash())
console.log('')
console.log('ServerSessionKey =', srpServer.getSessionKey())
console.log('ClientSessionKey =', srpClient.getSessionKey())
console.log('')
const passed = srpServer.getSessionKey().equals(srpClient.getSessionKey())
console.log(`Test Results: ${passed ? 'PASSED!' : 'FAILED!'}`)
