package p1;

import java.util.Arrays;
import p1.AuthEncryptor.MAC;

public class AuthDecryptor {
	// This class is used to decrypt and authenticate a sequence of values that were encrypted 
	//     by an AuthEncryptor.

	public static final int KeySizeBytes = AuthEncryptor.KeySizeBytes;
	public static final int KeySizeBits = AuthEncryptor.KeySizeBits;

	public static final int NonceSizeBytes = StreamCipher.NonceSizeBytes;
        
        StreamCipher streamCipher;
        MAC mac;


	public AuthDecryptor(byte[] key) {
		assert key.length == KeySizeBytes;
                mac = new MAC(key);
                streamCipher = new StreamCipher(key);
	}

	public byte[] decrypt(byte[] in, byte[] nonce, boolean nonceIncluded) {
		// Decrypt and authenticate the contents of <in>.  The value passed in will normally
		//    have been created by calling encrypt() with the same nonce in an AuthEncryptor 
		//    that was initialized with the same key as this AuthDecryptor.
		// If <nonceIncluded> is true, then the nonce has been included in <in>, and
		//    the value passed in as <nonce> will be disregarded.
		// If <nonceIncluded> is false, then the value of <nonce> will be used.
		// If the integrity of <in> cannot be verified, then this method returns null.   Otherwise it returns 
		//    a newly allocated byte-array containing the plaintext value that was originally 
		//    passed to encrypt().
                int MessageLength = in.length - MAC.Length;
                if (nonceIncluded) MessageLength -= NonceSizeBytes;
                byte[] ciphertext = new byte[MessageLength];
                byte[] MACode = new byte[MAC.Length];
                System.arraycopy(in, 0, ciphertext, 0, MessageLength);
                System.arraycopy(in, MessageLength, MACode, 0, MAC.Length);
                if (nonceIncluded) {
                        nonce = new byte[NonceSizeBytes];
                        System.arraycopy(in, MessageLength+MAC.Length, nonce, 0, NonceSizeBytes);
                }
                
                if (Arrays.equals(mac.find(ciphertext),MACode)) {
                        streamCipher.setNonce(nonce);
                        byte[] out = new byte[MessageLength];
                        streamCipher.cryptBytes(ciphertext, 0, out, 0, MessageLength);
                        return out;
                } else return null;
	}
        
        public static void main(String[] args) {          
                System.out.println("testing AuthEncryptor and AuthDecryptor");
                
				byte[] k = new byte[KeySizeBytes];
                for(int i=0; i<KeySizeBytes; ++i)    k[i] = (byte)(i+4);
                
                byte[] nonce = new byte[StreamCipher.NonceSizeBytes];
                for (int i=0;i<StreamCipher.NonceSizeBytes;i++) nonce[i]=(byte)(i+5); 
                
                byte[] testBytes = {(byte) 0x6f, (byte) 0xb1, (byte) 0x23};
                for (int i=0;i<testBytes.length;i++) System.out.print(testBytes[i] + ", ");
                System.out.println("");
                AuthEncryptor enTester = new AuthEncryptor(k);
                byte[] testCipher = enTester.encrypt(testBytes, nonce, false);
                for (int i=0;i<testBytes.length;i++) System.out.print(testCipher[i] + ", ");
                System.out.println("");
                AuthDecryptor deTester = new AuthDecryptor(k);
                byte[] testDecipher = deTester.decrypt(testCipher, nonce, false);
                for (int i=0;i<testBytes.length;i++) System.out.print(testDecipher[i]+", ");
                System.out.println("");
        }
}