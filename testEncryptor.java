import java.util.Random;

public class testEncryptor {

    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static void main(String[] args) {
        Random r = new Random();
        byte[] seed = new byte[32];
        r.nextBytes(seed);
        PRGen rand = new PRGen(seed);
        byte[] key = new byte[KEY_SIZE_BYTES];
        rand.nextBytes(key);

        byte[] nonce = new byte[8];
        PRGen nonceGen = new PRGen(key);
        nonceGen.nextBytes(nonce);
        


        AuthEncryptor encryptor = new AuthEncryptor(key);
        byte[] test1 = {0x00, 0x01, 0x02, 0x03, 0x04};
        byte[] test2 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};

        Util432s.printByteArray(test2);

        byte[] output1 = encryptor.authEncrypt(test2, nonce, true);
        byte[] output2 = encryptor.authEncrypt(test2, nonce, false);
        System.out.println();
        System.out.println("length with nonce: " + output1.length);
        System.out.println("length without nonce: " + output2.length);
        for (int i = 0; i < output2.length; i++) {
            if (output1[i] != output2[i]) {
                System.out.println("Not equal at: " + i);
                break;
            }
        }
        for(byte b: output1) System.out.print(b + " ");
        System.out.println();
        for(byte b: output2) System.out.print(b + " ");
        System.out.println();

        AuthDecryptor decryptor = new AuthDecryptor(key);

        byte[] decrypted1 = decryptor.authDecrypt(output1);
        byte[] decrypted2 = decryptor.authDecrypt(output2, nonce);
        Util432s.printByteArray(decrypted1);
        System.out.println();
        Util432s.printByteArray(decrypted2);
    }
}