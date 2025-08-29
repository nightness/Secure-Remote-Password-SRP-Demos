/**
 * SHA3-256 Test Vectors
 * Based on NIST FIPS 202 test vectors
 */
public class SHA3Test {
    
    static class TestVector {
        String input;
        String expected;
        String description;
        
        TestVector(String input, String expected, String description) {
            this.input = input;
            this.expected = expected;
            this.description = description;
        }
    }
    
    private static final TestVector[] TEST_VECTORS = {
        new TestVector("", 
                      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                      "Empty string"),
        new TestVector("abc", 
                      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                      "Short ASCII input"),
        new TestVector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
                      "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
                      "Longer ASCII input"),
        new TestVector(repeatString("a", 1000000), 
                      "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
                      "1 million 'a' characters")
    };
    
    public static boolean runSHA3Tests() {
        System.out.println("=== SHA3-256 Custom Implementation Tests ===");
        boolean allPassed = true;
        
        for (int i = 0; i < TEST_VECTORS.length; i++) {
            TestVector test = TEST_VECTORS[i];
            System.out.println("\\nTest " + (i + 1) + ": " + test.description);
            
            long startTime = System.nanoTime();
            String result = SHA3Custom.hash(test.input);
            long endTime = System.nanoTime();
            
            boolean passed = result.equals(test.expected);
            System.out.println("Input length: " + test.input.length() + " chars");
            System.out.println("Expected: " + test.expected);
            System.out.println("Got:      " + result);
            System.out.println("Result:   " + (passed ? "PASS" : "FAIL"));
            System.out.println("Time:     " + ((endTime - startTime) / 1000000.0) + "ms");
            
            if (!passed) {
                allPassed = false;
            }
        }
        
        System.out.println("\\n=== Summary ===");
        System.out.println("Overall result: " + (allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED"));
        
        return allPassed;
    }
    
    private static String repeatString(String str, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }
    
    public static void main(String[] args) {
        System.exit(runSHA3Tests() ? 0 : 1);
    }
}