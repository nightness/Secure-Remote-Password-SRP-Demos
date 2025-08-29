using System;
using System.Diagnostics;
using System.Text;
using SRP6;

/**
 * SHA3-256 Test Vectors
 * Based on NIST FIPS 202 test vectors
 */
public class SHA3Test
{
    public class TestVector
    {
        public string Input { get; set; }
        public string Expected { get; set; }
        public string Description { get; set; }

        public TestVector(string input, string expected, string description)
        {
            Input = input;
            Expected = expected;
            Description = description;
        }
    }

    private static readonly TestVector[] TEST_VECTORS = {
        new TestVector("", 
                      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                      "Empty string"),
        new TestVector("abc", 
                      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                      "Short ASCII input"),
        new TestVector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
                      "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
                      "Longer ASCII input"),
        new TestVector(new string('a', 1000000), 
                      "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
                      "1 million 'a' characters")
    };

    public static bool RunSHA3Tests()
    {
        Console.WriteLine("=== SHA3-256 Custom Implementation Tests ===");
        bool allPassed = true;

        for (int i = 0; i < TEST_VECTORS.Length; i++)
        {
            var test = TEST_VECTORS[i];
            Console.WriteLine($"\\nTest {i + 1}: {test.Description}");
            
            var stopwatch = Stopwatch.StartNew();
            string result = SHA3Custom.Hash(test.Input);
            stopwatch.Stop();
            
            bool passed = string.Equals(result, test.Expected, StringComparison.OrdinalIgnoreCase);
            Console.WriteLine($"Input length: {test.Input.Length} chars");
            Console.WriteLine($"Expected: {test.Expected}");
            Console.WriteLine($"Got:      {result}");
            Console.WriteLine($"Result:   {(passed ? "PASS" : "FAIL")}");
            Console.WriteLine($"Time:     {stopwatch.Elapsed.TotalMilliseconds:F2}ms");
            
            if (!passed)
            {
                allPassed = false;
            }
        }

        Console.WriteLine("\\n=== Summary ===");
        Console.WriteLine($"Overall result: {(allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED")}");
        
        return allPassed;
    }

}