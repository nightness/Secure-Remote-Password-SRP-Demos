using System;
using System.Text;
using SRP6;

namespace Program
{
    class Program
    {
        #region Identity variables
        private static string Username = "TEST";
        private static string Password = "test";
        #endregion

        #region Preestablished SRP6 variables
        // These should be preestablished between the client and server
        private const int Generator = 0x0A;
        private const int SafePrimeLength = 256;
        private const int SaltBitLength = 512;
        private const int ScramblerBitLength = 256;
        #endregion

        static void Main(string[] args)
        {
            // Run SHA3 tests if requested
            if (args.Length > 0 && args[0].ToLower() == "sha3test")
            {
                Console.WriteLine("Running SHA3 tests...");
                Environment.Exit(SHA3Test.RunSHA3Tests() ? 0 : 1);
                return;
            }

            Console.WriteLine("=== SRP6 Demo ===");

            // The modulus is a safe prime number that both client and server know before authentication.
			String modulus = "20E176988FD33DE7AE0D296BF805A49F3F45B92FB59036DCC9F0624B89B2DB67";

            Console.WriteLine(Environment.NewLine);

            // Run the test automatically without user input
            RunTest(modulus);
        }

		private static ConsoleKey GetKey()
		{
			ConsoleKeyInfo result = Console.ReadKey(true);
			if (result.Key != ConsoleKey.Enter)
				Console.Write(result.KeyChar);
			return result.Key;
		}

        /// <summary>Gets the iteration count</summary>
        /// <returns>The iteration count</returns>
        private static int GetIterationCount()
        {
            Console.WriteLine();
            while (true)
			{
                Console.Write("How many iterations? ");
                string? textAmount = Console.ReadLine();
                try
				{                   
                    int count = Convert.ToInt32(textAmount);
                    Console.WriteLine();
                    return count;
                }
                catch { }
            }
        }

        private static string GenerateRandomString(int length = 128)
        {
            // 32-126, excluding 58 (reserved for separation of username and password in this example)
            byte[] bytes = new byte[length];
            Random rand = new Random();
            for (int i = 0; i < length; i++)
            {
                byte b = (byte)rand.Next(32, 126);
                if (b == 58)
                    i--;
                else
                    bytes[i] = b;
            }
            return Encoding.ASCII.GetString(bytes);
        }

        /// <summary>Runs the test</summary>
        /// <returns>Test results</returns>
        /// <param name='modulus'>The modulus string</param>
        /// <param name='silent'>If set to <c>true</c>, this function will not write to the console</param>
		private static bool RunTest(String modulus, bool silent = false)
		{
            // Generate an identity hash. The username and password are deliminated with a colon. For this
            // to work properly, the username can not contain a colon. Else the following condition could
            // occur... Example "user:1:2", is that "user:1" + pass "2", or "user" + pass "1:2"?
            //
            // The identity hash is generated and sent by the client (for each new session), and saved on the
            // server (so username and password isn't).
            byte[] identityHash = Encoding.Unicode.GetBytes((Username + ":" + Password)).Sha3Hash();

			// Server generates (and sends to client) public-key, scrambler, and salt
			var srpServer = new Srp6(identityHash, modulus, Generator, SaltBitLength, ScramblerBitLength);

			// Client generates (and sends to server) it's public key
			var srpClient = new Srp6(identityHash, modulus, Generator, srpServer.Salt.ToHexString());

			// The client can set it's SessionKey now
			srpClient.SetSessionKey(srpServer.PublicKey.ToHexString(), srpServer.Scrambler.ToHexString());

			// The server receives client's public key, server can now set it's SessionKey
			srpServer.SetSessionKey(srpClient.PublicKey.ToHexString());

            // Test the Encrypt & Decrypt methods
            const string startingText = "Hello";
            string encryptedText = srpServer.Encrypt(startingText);
            string decryptedText = srpClient.Decrypt(encryptedText);

			// Results
			if (!silent)
            {
				Console.WriteLine(Environment.NewLine);
				Console.WriteLine("Modulus = " + srpServer.Modulus.ToHexString());
				Console.WriteLine("Multiplier = " + srpServer.Multiplier.ToHexString());
				Console.WriteLine("Generator = " + srpServer.Generator.ToHexString());
				Console.WriteLine("Salt = " + srpServer.Salt.ToHexString());
				Console.WriteLine("IdentityHash = " + srpServer.IdentityHash.ToHexString());
				Console.WriteLine("Verifier = " + srpServer.Verifier.ToHexString());
				Console.WriteLine();
				Console.WriteLine("ServerPrivateKey(b)= " + srpServer.PrivateKey.ToHexString());
				Console.WriteLine("ServerPublicKey(B)= " + srpServer.PublicKey.ToHexString());
				Console.WriteLine("Scramber(u)= " + srpServer.Scrambler.ToHexString());
				Console.WriteLine();
				Console.WriteLine("ClientPrivateKey(a) = " + srpClient.PrivateKey.ToHexString());
				Console.WriteLine("ClientPublicKey(A)= " + srpClient.PublicKey.ToHexString());
				Console.WriteLine("ClientIdentityHash(x) = " + srpClient.IdentityHash.ToHexString());
				Console.WriteLine();
				Console.WriteLine("ServerSessionKey = " + srpServer.SessionKey.ToHexString());
				Console.WriteLine("ClientSessionKey = " + srpClient.SessionKey.ToHexString());
                Console.WriteLine();
                Console.WriteLine("Starting Text = " + startingText);
                Console.WriteLine("Encrypted Text = " + encryptedText);
                Console.WriteLine("Decrypted Text = " + decryptedText);
			}

            // Both client and server now have the same SessionKey to encrypt/decrypt
            // communications. The SessionKey was never exchanged over the network.
			// And without knowing the identity hash, a hacker can't sniff communications.
			return srpServer.SessionKey.Equals(srpClient.SessionKey);
		}

        /// <summary>Generates a safe prime</summary>
        /// <returns>The safe prime as a string</returns>
		private static string GenerateSafePrime()
		{
			var random = new Random();
			var bitInt = BigIntegerExtensions.GenerateSafePrime(SafePrimeLength, 1, random);
            // The modulus is a safe prime
			while (!bitInt.IsSafePrime(100))
			{
				bitInt = BigIntegerExtensions.GenerateSafePrime(SafePrimeLength, 1, random);
			}
			return bitInt.ToString("X2");
		}

    }
}
