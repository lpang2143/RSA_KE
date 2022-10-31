import java.util.Arrays;

/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/
public class AuthDecryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;
    public static final int MAC_SIZE_BYTES = AuthEncryptor.MAC_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS
    // global variables to save separate keys
    private byte[] decryptKey;
    private byte[] macKey;

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        // IMPLEMENT THIS
        // generating PRGen seeded from given key
        decryptKey = new byte[KEY_SIZE_BYTES];
        macKey = new byte[KEY_SIZE_BYTES];
        PRGen gen = new PRGen(key);
        // initializing instance variables
        gen.nextBytes(decryptKey);
        gen.nextBytes(macKey);
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in) {
        // IMPLEMENT THIS
        // separating in into new_in and nonce
        byte[] new_in = new byte[in.length - NONCE_SIZE_BYTES];
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        System.arraycopy(in, in.length - NONCE_SIZE_BYTES, nonce, 0, NONCE_SIZE_BYTES);
        System.arraycopy(in, 0, new_in, 0, in.length - NONCE_SIZE_BYTES);
        // calling overloaded authDecrypt using separated functions
        return authDecrypt(new_in, nonce);
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;
        // IMPLEMENT THIS
        // separating in into encrypted and MAC
        byte[] encrypted = new byte[in.length - MAC_SIZE_BYTES];
        byte[] mac_input = new byte[encrypted.length + NONCE_SIZE_BYTES];
        byte[] mac = new byte[MAC_SIZE_BYTES];
        byte[] out = new byte[encrypted.length];
        System.arraycopy(in, 0, encrypted, 0, encrypted.length);
        System.arraycopy(in, in.length - MAC_SIZE_BYTES, mac, 0, MAC_SIZE_BYTES);

        // creating mac_input to test authenticity
        System.arraycopy(encrypted, 0, mac_input, 0, encrypted.length);
        System.arraycopy(nonce, 0, mac_input, encrypted.length, NONCE_SIZE_BYTES);
        // generaing MAC PRF and eval using MAC_input
        PRF mac_PRF = new PRF(macKey);
        byte[] sample_mac = mac_PRF.eval(mac_input);

        // if generated MAC doesn't equal sent mac, return null
        if (!Arrays.equals(sample_mac, mac)) {
            return null;
        }

        // decrypt encrypted using streamcipher and return out array
        StreamCipher cipher = new StreamCipher(decryptKey, nonce);
        cipher.cryptBytes(encrypted, 0, out, 0, encrypted.length);
        return out;
    }
}
