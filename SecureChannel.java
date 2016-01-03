import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

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

        private final int NonceSize = AuthEncryptor.NonceSizeBytes;
        byte[] k;
        PRGen prgen;

        public SecureChannel(InputStream inStr, OutputStream outStr,
                PRGen rand, boolean iAmServer,
                RSAKey serverKey) throws IOException {
                // if iAmServer==false, then serverKey is the server's *public* key
                // if iAmServer==true, then serverKey is the server's *private* key

                super(inStr, outStr);
                prgen = rand;
                if (iAmServer) {
                        byte[] ClientNonce = super.receiveMessage();
                        byte[] ServerNonce = new byte[NonceSize];
                        prgen.nextBytes(ServerNonce);
                        super.sendMessage(ServerNonce);
                        
                        KeyExchange DHKey = new KeyExchange(prgen);
                        byte[] message = DHKey.prepareOutMessage();
                        byte[] signature = serverKey.sign(message, prgen);
                        super.sendMessage(message);
                        super.sendMessage(signature);
                        
                        byte[] PMS = DHKey.processInMessage(super.receiveMessage());
                        k = cryptHash(PMS, concat("master secret".getBytes(), ClientNonce, ServerNonce));
                        
                        byte[] serverVerification = cryptHash(k, concat(received, sent));
                        byte[] clientExpected = cryptHash(k, concat(sent, received));

                        byte[] clientVerification = super.receiveMessage();
                        if (!(Arrays.equals(clientVerification, clientExpected))) close();
                        
                        super.sendMessage(serverVerification);
                } else {
                        byte[] ClientNonce = new byte[NonceSize];
                        prgen.nextBytes(ClientNonce);
                        super.sendMessage(ClientNonce);
                        byte[] ServerNonce = super.receiveMessage();

                        KeyExchange DHKey = new KeyExchange(prgen);
                        byte[] message = super.receiveMessage();
                        byte[] signature = super.receiveMessage();

                        if (!(serverKey.verifySignature(message, signature))) close();
                        super.sendMessage(DHKey.prepareOutMessage());
                        byte[] PMS = DHKey.processInMessage(message);
                        k = cryptHash(PMS, concat("master secret".getBytes(), ClientNonce, ServerNonce));
                        
                        byte[] clientVerification = cryptHash(k, concat(received, sent));
                        byte[] serverExpected = cryptHash(k, concat(sent, received));

                        super.sendMessage(clientVerification);
                        byte[] serverVerification = super.receiveMessage();
                        if (!(Arrays.equals(serverVerification, serverExpected))) close();
                }
        }

        public void sendMessage(byte[] message) throws IOException {
                byte[] nonce = new byte[NonceSize];
                prgen.nextBytes(nonce);
                AuthEncryptor crypt = new AuthEncryptor(k);
                byte[] ciphertext = crypt.encrypt(message, nonce, true);
                byte[] hash = cryptHash(k, sent);
                super.sendMessage(concat(ciphertext, hash));
        }

        public byte[] receiveMessage() throws IOException {
                byte[] expectedHash = cryptHash(k, received);
                
                byte[] in = super.receiveMessage();
                byte[] ciphertext = Arrays.copyOf(in, (in.length - PRF.OutputSizeBytes));
                byte[] hash = Arrays.copyOfRange(in, ciphertext.length, in.length);
                if (!(Arrays.equals(expectedHash, hash))) close();
                
                AuthDecryptor crypt = new AuthDecryptor(k);
                return crypt.decrypt(ciphertext, null, true);
        }

        public static byte[] cryptHash(byte[] key, byte[] msg) {
                PRF prf = new PRF(key);
                return prf.eval(msg);
        }
}
