/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;
    public static final int MAC_SIZE_BYTES = 32;

    // Instance variables.
    // IMPLEMENT THIS
    // global variables to save separate keys
    private byte[] encryptKey;
    private byte[] macKey;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        // IMPLEMENT THIS
        // generating new PRGen seeded by key
        encryptKey = new byte[KEY_SIZE_BYTES];
        macKey = new byte[KEY_SIZE_BYTES];
        PRGen gen = new PRGen(key);
        // generating 2 instance keys using PRGen
        gen.nextBytes(encryptKey);
        gen.nextBytes(macKey);
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are protected against those who do not
    //     know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the output.
    // Returns a newly allocated byte[] containing the authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        // IMPLEMENT THIS
        assert nonce.length == NONCE_SIZE_BYTES;
        // local variables to store encrypted, mac and output
        byte[] encrypted = new byte[in.length];
        byte[] mac = new byte[MAC_SIZE_BYTES];
        byte[] mac_input = new byte[in.length + NONCE_SIZE_BYTES];
        byte[] out;
        // encrypting using encrypt key and saving in encrypted array
        StreamCipher cipher = new StreamCipher(encryptKey, nonce);
        cipher.cryptBytes(in, 0, encrypted, 0, in.length);

        // generating PRF to serve as MAC function
        PRF mac_PRF = new PRF(macKey);
        // concatenating encrypted and nonce into mac_input
        System.arraycopy(encrypted, 0, mac_input, 0, encrypted.length);
        System.arraycopy(nonce, 0, mac_input, encrypted.length, NONCE_SIZE_BYTES);
        // generating 32 byte output MAC
        mac = mac_PRF.eval(mac_input);

        // if include nonce, change length of out byte array
        if(includeNonce) {
            out = new byte[in.length + NONCE_SIZE_BYTES + MAC_SIZE_BYTES];
        } else {
            out = new byte[in.length + MAC_SIZE_BYTES];
        }

        // copy encrypted and MAC to output array
        System.arraycopy(encrypted, 0, out, 0, encrypted.length);
        System.arraycopy(mac, 0, out, encrypted.length, MAC_SIZE_BYTES);

        // include nonce if needed
        if(includeNonce) {
            int nonceIndex = encrypted.length + MAC_SIZE_BYTES;
            System.arraycopy(nonce, 0, out, nonceIndex, NONCE_SIZE_BYTES);
        }
        return out;
    }
}
