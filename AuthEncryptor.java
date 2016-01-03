package p1;

public class AuthEncryptor {
	// This class is used to compute the authenticated encryption of values.  
	//     Authenticated encryption protects the confidentiality of a value, so that the only 
	//     way to recover the initial value is to do authenticated decryption of the value using the 
	//     same key and nonce that were used to encrypt it.   At the same time, authenticated encryption
	//     protects the integrity of a value, so that a party decrypting the value using
	//     the same key and nonce (that were used to decrypt it) can verify that nobody has tampered with the
	//     value since it was encrypted.

	public static final int KeySizeBytes = 32;   // IMPLEMENT THIS
	public static final int KeySizeBits = KeySizeBytes*8;

	public static final int NonceSizeBytes = StreamCipher.NonceSizeBytes;
        
        StreamCipher streamCipher;
        MAC mac;

	public AuthEncryptor(byte[] key) {
		assert key.length == KeySizeBytes;
                streamCipher = new StreamCipher(key);
                mac = new MAC(key);
	}
        
        //I don't know if we can create new class files, so this will go here for now.
        public static class MAC {
                private byte[] MACKey;
                public static final int Length = PRF.OutputSizeBytes; //TODO: Consider shorter MAC length
                public MAC(byte[] key) {
                        assert key.length == KeySizeBytes;
                        PRF prf = new PRF(key);
                        MACKey = prf.eval(key);
                }
                public byte[] find(byte[] m) {
                        PRF prf = new PRF(MACKey);
                        return prf.eval(m);       
                }
        }

	public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
		// Encrypts the contents of <in> so that its confidentiality and 
		//    integrity are protected against would-be attackers who do 
		//    not know the key that was used to initialize this AuthEncryptor.
		// Callers are forbidden to pass in the same nonce more than once;
		//    but this code will not check for violations of this rule.
		// The nonce will be included as part of the output iff <includeNonce>
		//    is true.  The nonce should be in plaintext if it is included.
		//
		// This returns a newly allocated byte[] containing the authenticated
		//    encryption of the input.
                
                int OutLen = in.length + MAC.Length;
                if (includeNonce) OutLen+=nonce.length;
                
                byte[] ciphertext = new byte[in.length];
                
                streamCipher.setNonce(nonce);
                streamCipher.cryptBytes(in, 0, ciphertext, 0, in.length);
                
                byte[] MACode = mac.find(ciphertext);

                byte[] out = new byte[OutLen];
                System.arraycopy(ciphertext, 0, out, 0, ciphertext.length);
                System.arraycopy(MACode, 0, out, ciphertext.length, MACode.length);
                if (includeNonce) System.arraycopy(nonce, 0, out, ciphertext.length+MACode.length, nonce.length);
                return out;
	}
}