import { SHA3_256 } from './lib/sha3';

/**
 * SHA3-256 Test Vectors
 * Based on NIST FIPS 202 test vectors
 */

interface TestVector {
    input: string;
    expected: string;
    description: string;
}

const TEST_VECTORS: TestVector[] = [
    {
        input: "",
        expected: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        description: "Empty string"
    },
    {
        input: "abc",
        expected: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        description: "Short ASCII input"
    },
    {
        input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        expected: "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        description: "Longer ASCII input"
    },
    {
        input: "a".repeat(1000000),
        expected: "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
        description: "1 million 'a' characters"
    }
];

function runSHA3Tests(): boolean {
    console.log("=== SHA3-256 Custom Implementation Tests ===");
    let allPassed = true;

    for (let i = 0; i < TEST_VECTORS.length; i++) {
        const test = TEST_VECTORS[i];
        console.log(`\\nTest ${i + 1}: ${test.description}`);
        
        const startTime = performance.now();
        const result = SHA3_256.hash(test.input);
        const endTime = performance.now();
        
        const passed = result === test.expected;
        console.log(`Input length: ${test.input.length} chars`);
        console.log(`Expected: ${test.expected}`);
        console.log(`Got:      ${result}`);
        console.log(`Result:   ${passed ? 'PASS' : 'FAIL'}`);
        console.log(`Time:     ${(endTime - startTime).toFixed(2)}ms`);
        
        if (!passed) {
            allPassed = false;
        }
    }

    console.log(`\\n=== Summary ===`);
    console.log(`Overall result: ${allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
    
    return allPassed;
}

// Run tests if this file is executed directly
if (require.main === module) {
    process.exit(runSHA3Tests() ? 0 : 1);
}

export { runSHA3Tests };