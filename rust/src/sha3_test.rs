use crate::sha3_custom::SHA3_256;
use std::time::Instant;

/**
 * SHA3-256 Test Vectors
 * Based on NIST FIPS 202 test vectors
 */

pub struct TestVector {
    pub input: &'static str,
    pub expected: &'static str,
    pub description: &'static str,
}

const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        input: "",
        expected: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        description: "Empty string",
    },
    TestVector {
        input: "abc",
        expected: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        description: "Short ASCII input",
    },
    TestVector {
        input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        expected: "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        description: "Longer ASCII input",
    },
];

pub fn run_sha3_tests() -> bool {
    println!("=== SHA3-256 Custom Implementation Tests ===");
    let mut all_passed = true;

    for (i, test) in TEST_VECTORS.iter().enumerate() {
        println!("\\nTest {}: {}", i + 1, test.description);
        
        let start_time = Instant::now();
        let result = if test.input.is_empty() {
            SHA3_256::hash(&[])
        } else {
            SHA3_256::hash_string(test.input)
        };
        let end_time = Instant::now();
        
        let passed = result == test.expected;
        println!("Input length: {} chars", test.input.len());
        println!("Expected: {}", test.expected);
        println!("Got:      {}", result);
        println!("Result:   {}", if passed { "PASS" } else { "FAIL" });
        println!("Time:     {:.2}ms", (end_time - start_time).as_secs_f64() * 1000.0);
        
        if !passed {
            all_passed = false;
        }
    }

    // Test with 1 million 'a' characters (separate due to size)
    println!("\\nTest 4: 1 million 'a' characters");
    let million_as = "a".repeat(1000000);
    let start_time = Instant::now();
    let result = SHA3_256::hash_string(&million_as);
    let end_time = Instant::now();
    
    let expected = "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1";
    let passed = result == expected;
    println!("Input length: {} chars", million_as.len());
    println!("Expected: {}", expected);
    println!("Got:      {}", result);
    println!("Result:   {}", if passed { "PASS" } else { "FAIL" });
    println!("Time:     {:.2}ms", (end_time - start_time).as_secs_f64() * 1000.0);
    
    if !passed {
        all_passed = false;
    }

    println!("\\n=== Summary ===");
    println!("Overall result: {}", if all_passed { "ALL TESTS PASSED" } else { "SOME TESTS FAILED" });
    
    all_passed
}