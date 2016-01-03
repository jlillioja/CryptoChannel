package p2;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class RSAKey {

        private BigInteger exponent;
        private BigInteger modulus;

        private static final int oaepK0 = 32; //in bytes
        private static final int oaepK1 = 32; //in bytes

        private int maxLength;
        private int rawLength;
        private int paddedLength;
        private int totalLength;

        public RSAKey(BigInteger theExponent, BigInteger theModulus) {
                exponent = theExponent;
                modulus = theModulus;
                System.out.print("modulus.bitlength + 1: ");System.out.println(modulus.bitLength() + 1);
                totalLength = ((modulus.bitLength()+1)/8);
                System.out.print("totalLength: ");System.out.println(totalLength);
                paddedLength = totalLength - oaepK0;
                rawLength = paddedLength - oaepK1;
                maxLength = rawLength - 4; //4 bytes for an int to say how much padding was added,
        }

        public BigInteger getExponent() {
                return exponent;
        }

        public BigInteger getModulus() {
                return modulus;
        }

        public byte[] encrypt(byte[] plaintext, PRGen prgen) {
                if (plaintext == null) {
                        throw new NullPointerException();
                }
                if (plaintext.length > (maxLength)) {
                        return null; //TODO: Consider throwing error
                }
                //byte[] paddedPlaintext = encodeOaep(plaintext, prgen);
                byte[] oaeptext = encodeOaep(addPadding(plaintext), prgen);
                byte[] ciphertext = RSACrypt(oaeptext);
                System.out.println("Exiting encrypt");
                return ciphertext;
        }

        public byte[] decrypt(byte[] ciphertext) {
                System.out.println("Entering decrypt");
                if (ciphertext == null) {
                        throw new NullPointerException();
                }
                byte[] oaepPlaintext = RSACrypt(ciphertext);
                System.out.print("OAEP Plaintext: ");System.out.println(Arrays.toString(oaepPlaintext));
                return removePadding(decodeOaep(oaepPlaintext));
        }

        public byte[] sign(byte[] message, PRGen prgen) {
                // Create a digital signature on <message>. The signature need
                //     not contain the contents of <message>--we will assume
                //     that a party who wants to verify the signature will already
                //     know which message this is (supposed to be) a signature on.
                if (message == null) {
                        throw new NullPointerException();
                }
                byte[] messageHash = Proj2Util.stretchedHash(message, maxLength);
                return encrypt(messageHash, prgen);
        }

        public boolean verifySignature(byte[] message, byte[] signature) {
                // Verify a digital signature. Returns true if  <signature> is
                //     a valid signature on <message>; returns false otherwise.
                //     A "valid" signature is one that was created by calling
                //     <sign> with the same message, using the other RSAKey that
                //     belongs to the same RSAKeyPair as this object.
                if ((message == null) || (signature == null)) {
                        throw new NullPointerException();
                }
                byte[] messageHash = Proj2Util.stretchedHash(message, maxLength);
                return (Arrays.equals(decrypt(signature), messageHash));
        }

        public int maxPlaintextLength() {
                // Return the largest N such that any plaintext of size N bytes
                //      can be encrypted with this key

                return maxLength;
        }

        // The next four methods are public to help us grade the assignment. In real life, these would
        // be private methods as there's no need to expose these methods as part of the public API
        public byte[] encodeOaep(byte[] input, PRGen prgen) {
                System.out.println("Entering encodeOaep");
                
                System.out.print("input: ");System.out.println(Arrays.toString(input));
                System.out.print("input.length: ");System.out.println(input.length);
                
                byte[] paddedInput = new byte[paddedLength];
                System.arraycopy(input,0,paddedInput,0,rawLength);
                Arrays.fill(paddedInput, rawLength, paddedLength, (byte)(0x0));
                
                System.out.print("paddedInput: ");System.out.println(Arrays.toString(paddedInput));
                System.out.print("paddedInput.length: ");System.out.println(paddedInput.length);

                byte[] r = new byte[oaepK0];
                prgen.nextBytes(r);
                System.out.print("r: ");System.out.println(Arrays.toString(r));
                
                PRGen G = new PRGen(r);
                byte[] Gr = new byte[paddedLength];
                G.nextBytes(Gr);
                byte[] X = new byte[paddedLength];
                for (int i = 0; i < paddedLength; i++) {
                        X[i] = (byte) (paddedInput[i] ^ Gr[i]);
                }

                PRGen H = new PRGen(X);
                byte[] Hx = new byte[oaepK0];
                H.nextBytes(Hx);
                byte[] Y = new byte[oaepK0];
                for (int i = 0; i < oaepK0; i++) {
                        Y[i] = (byte) (r[i] ^ (byte) Hx[i]);
                }

                byte[] out = new byte[totalLength];
                System.arraycopy(X, 0, out, 0, X.length);
                System.arraycopy(Y, 0, out, X.length, Y.length);
                System.out.print("out: ");System.out.println(Arrays.toString(out));
                System.out.print("out.length: ");System.out.println(out.length);
                System.out.println("Exiting encodeOaep");
                return out;
        }

        public byte[] decodeOaep(byte[] input) {
                System.out.println("Entering decodeOaep");
                
                System.out.print("input: ");System.out.println(Arrays.toString(input));
                System.out.print("input.length: ");System.out.println(input.length);
                
                byte[] X = new byte[paddedLength];
                System.arraycopy(input, 0, X, 0, paddedLength);
                
                byte[] Y = new byte[oaepK0];
                System.arraycopy(input, paddedLength, Y, 0, oaepK0);

                PRGen H = new PRGen(X);
                byte[] Hx = new byte[oaepK0];
                H.nextBytes(Hx);
                byte[] r = new byte[oaepK0];
                for (int i = 0; i < oaepK0; i++) {
                        r[i] = (byte) (Y[i] ^ Hx[i]);
                }
                
                System.out.print("r: ");
                System.out.println(Arrays.toString(r));
                
                PRGen G = new PRGen(r);
                byte[] Gr = new byte[paddedLength];
                G.nextBytes(Gr);
                byte[] message = new byte[paddedLength];
                for (int i = 0; i < paddedLength; i++) {
                        message[i] = (byte) (X[i] ^ Gr[i]);
                }
                System.out.println("Exiting decodeOaep");
                return message;
        }

        public byte[] addPadding(byte[] input) { //Pads to n-k0-k1 = maxLength+4
                byte[] paddedInput = new byte[maxLength+4];
                System.arraycopy(input, 0, paddedInput, 0, input.length);
                byte[] padLength = intToByteArray(maxLength - input.length);
                System.arraycopy(padLength, 0, paddedInput, maxLength, 4);
                return paddedInput;
        }

        public byte[] removePadding(byte[] input) {
                System.out.println("Entering removePadding");
                byte[] padLength = new byte[4];
                System.arraycopy(input, maxLength, padLength, 0, 4);
                int padLengthInt = byteArrayToInt(padLength);
                System.out.println(padLengthInt);
                byte[] unpaddedInput = new byte[maxLength - padLengthInt];
                System.arraycopy(input, 0, unpaddedInput, 0, maxLength - padLengthInt);
                return unpaddedInput;
        }

        public byte[] RSACrypt(byte[] text) {
                System.out.println("Entering RSACrypt");
                
                System.out.print("text: ");System.out.println(Arrays.toString(text));
                System.out.print("text.length: ");System.out.println(text.length);
                
                BigInteger inputInt = Proj2Util.bytesToBigInteger(text);
                System.out.print("inputInt: ");System.out.println(inputInt);
                
                BigInteger cryptInt = inputInt.modPow(exponent, modulus); //gives wrong cryptInt when using oaep
                System.out.print("cryptInt: ");System.out.println(cryptInt);
                
                byte[] cryptText = Proj2Util.bigIntegerToBytes(cryptInt, (cryptInt.bitLength()/8)+1);
                System.out.print("cryptText: ");System.out.println(Arrays.toString(cryptText));
                System.out.println("Exiting RSACrypt");
                return cryptText;
        }

        private byte[] intToByteArray(int n) {
                byte[] a = ByteBuffer.allocate(4).putInt(n).array();
                return a;
        }

        private int byteArrayToInt(byte[] a) {
                System.out.println("byteArrayToInt");
                System.out.println(Arrays.toString(a));
                System.out.println(a.length);
                int n = ByteBuffer.wrap(a).getInt();
                System.out.println(n);
                return n;
        }
}
