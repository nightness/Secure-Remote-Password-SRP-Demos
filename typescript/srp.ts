import { SRP6Client, SRP6Server } from "./lib/srp";

// Must be a prime number
const modulus =
  "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";

const srpServer = new SRP6Server("TEST", "test", modulus, 3, 256, 128);
const srpClient = new SRP6Client(
  "TEST",
  "test",
  modulus,
  3,
  srpServer.getSalt()
);

// This is the information that would normally be exchanged over the network connection
srpServer.setSessionKey(srpClient.getPublicKey());
srpClient.setSessionKey(srpServer.getPublicKey(), srpServer.getScrambler());

console.log("=== SRP6 Demo Started ===");
console.log("Modulus =", srpServer.getModulus().toString());
console.log("Multiplier =", srpServer.getMultiplier().toString());
console.log("Generator= ", srpServer.getGenerator().toString());
console.log("Salt =", srpServer.getSalt().toString());
console.log("IdentityHash =", srpServer.getIdentityHash().toString());
console.log("Verifier =", srpServer.getVerifier().toString());
console.log("");
console.log("ServerPrivateKey (b) =", srpServer.getPrivateKey().toString());
console.log("ServerPublicKey (B) = ", srpServer.getPublicKey().toString());
console.log("Scrambler (u)=", srpServer.getScrambler().toString());
console.log("");
console.log("ClientPrivateKey (a) =", srpClient.getPrivateKey().toString());
console.log("ClientPublicKey (A)=", srpClient.getPublicKey().toString());
console.log("ClientIdentityHash (x) =", srpClient.getIdentityHash().toString());
console.log("");
console.log("ServerSessionKey =", srpServer.getSessionKey().toString());
console.log("ClientSessionKey =", srpClient.getSessionKey().toString());
console.log("");

const passed = srpServer.getSessionKey().equals(srpClient.getSessionKey());
console.log(`Test Results: ${passed ? "PASSED!" : "FAILED!"}`);
