import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides 
    //    authenticated encryption for the messages that pass
    //    over the channel.   It also guarantees that messages are delivered 
    //    on the receiving end in the same order they were sent (returning
    //    null otherwise).  Also, when the channel is first set up,
    //    the client authenticates the server's identity, and the necessary
    //    steps are taken to detect any man-in-the-middle (and to close the
    //    connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    //    calls to the underlying InsecureChannel.

    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;

    // Instance Variables
    // stores symmetric key negotiated between server and client
    private byte[] symmetricKey = new byte[KEY_SIZE_BYTES];
    // shared secret negotiated between server and client
    private byte[] secret;
    // AuthEncryptor and Decryptor seeded using symmetricKey
    private AuthEncryptor encrypt;
    private AuthDecryptor decrypt;
    // PRGen for creating nonces, seeded using symmetricKey
    private PRGen nonceGen;

    public SecureChannel(InputStream inStr, OutputStream outStr,
                         PRGen rand, boolean iAmServer,
                         RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key

        super(inStr, outStr);
        // IMPLEMENT THIS
        // creates a KeyExchange object, preparing an out, sending,
        // and processing for shared secret
        KeyExchange exchange = new KeyExchange(rand, iAmServer);
        byte[] message = exchange.prepareOutMessage();
        super.sendMessage(message);
        byte[] received = super.receiveMessage();
        secret = exchange.processInMessage(received);
        
        // seeding a PRGen to create symmetrickKey
        PRGen keyGen = new PRGen(secret);
        keyGen.nextBytes(symmetricKey);

        // seeding new AuthEn/Decryptor and PRGen for nonces
        encrypt = new AuthEncryptor(symmetricKey);
        decrypt = new AuthDecryptor(symmetricKey);
        
        nonceGen = new PRGen(symmetricKey);

        // creating and sending RSA signature if server
        if (iAmServer) {
            byte[] signature = serverKey.sign(secret, rand);
            super.sendMessage(signature);
        } 
        // receiving and verifying signature if client
        // delete secrets and close channel if not verified
        else {
            byte[] signature = super.receiveMessage();
            if (!serverKey.verifySignature(secret, signature)) {
                symmetricKey = null;
                encrypt = null;
                decrypt = null;
                nonceGen = null;
                super.close();
            }
        }
    }

    public void sendMessage(byte[] message) throws IOException {
        // IMPLEMENT THIS
        // generating next nonce using nonceGen
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        nonceGen.nextBytes(nonce);
        // encrypting using AuthEncrypt with generated nonce and sending
        byte[] encrypted = encrypt.authEncrypt(message, nonce, true);
        super.sendMessage(encrypted);
    }

    public byte[] receiveMessage() throws IOException {
        // IMPLEMENT THIS
        // receiving the message and iterating nonce PRGen
        byte[] encrypted = super.receiveMessage();
        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        nonceGen.nextBytes(nonce);
        // decrypting and returning message
        byte[] message = decrypt.authDecrypt(encrypted);
        return message;
    }
}
