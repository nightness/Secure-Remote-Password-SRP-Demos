using System;

namespace SRP6
{
    public static class Sha3Extensions
    {
        public static byte[] Sha3Hash(this byte[] arg1)
        {
            try
            {
                if ((arg1 == null) || (arg1.Length == 0))
                    throw new InvalidOperationException("arg1 can not be null or have a length of zero.");

                string hex = SHA3Custom.Hash(arg1);
                return HexToBytes(hex);
            }
            catch (Exception e)
            {
                Console.WriteLine("Sha3Hash: " + e.Message);
                return Array.Empty<byte>();
            }
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}