public class SHA3Util {
    
    public static byte[] sha3Hash(byte[] input) {
        String hex = SHA3Custom.hash(input);
        return hexToBytes(hex);
    }
    
    public static byte[] sha3Hash(byte[] input1, byte[] input2) {
        byte[] combined = new byte[input1.length + (input2 != null ? input2.length : 0)];
        System.arraycopy(input1, 0, combined, 0, input1.length);
        if (input2 != null) {
            System.arraycopy(input2, 0, combined, input1.length, input2.length);
        }
        return sha3Hash(combined);
    }
    
    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }
}