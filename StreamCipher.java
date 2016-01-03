package p1;
import p1.PRGen;
import p1.PRF;
import static p1.PRGen.KeySizeBytes;
public class StreamCipher {
	// This class encrypts or decrypts a stream of bytes, using a stream cipher.

	public static final int KeySizeBytes = 32;  // IMPLEMENT THIS
	public static final int KeySizeBits = KeySizeBytes*8;

	public static final int NonceSizeBytes = 8;
	public static final int NonceSizeBits = NonceSizeBytes*8;
        
        private byte[] seed;
        private byte[] initkey;
        private boolean nonceSet;
        PRGen prgen;


	public StreamCipher(byte[] key) {
		// <key> is the key, which must be KeySizeBytes bytes in length.

		assert key.length == KeySizeBytes;
                initkey = key;
                seed = new byte[KeySizeBytes];
                System.arraycopy(key, 0, seed, 0, KeySizeBytes);
                nonceSet = false;
	}

	public void setNonce(byte[] arr, int offset){
		// Reset to initial state, and set a new nonce.
		// The nonce is in arr[offset] thru arr[offset+NonceSizeBytes-1].
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.
                
		PRF prf = new PRF(initkey);
                prf.update(initkey);
                prgen = new PRGen(prf.eval(arr, offset, NonceSizeBytes));
                nonceSet=true;
	}

	public void setNonce(byte[] nonce) {
		// Reset to initial state, and set a new nonce
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		assert nonce.length == NonceSizeBytes;
		setNonce(nonce, 0);
	}

	public byte cryptByte(byte in) {
		// Encrypt/decrypt the next byte in the stream
                assert nonceSet;
                in = (byte) (in ^((byte) prgen.next(8)));
		return in;
	}

	public void cryptBytes(byte[] inBuf, int inOffset, 
			byte[] outBuf, int outOffset, 
			int numBytes) {
		// Encrypt/decrypt the next <numBytes> bytes in the stream
		// Take input bytes from inBuf[inOffset] thru inBuf[inOffset+numBytes-1]
		// Put output bytes at outBuf[outOffset] thru outBuf[outOffset+numBytes-1];

		for (int i=0;i<numBytes;i++) outBuf[i+outOffset] = cryptByte(inBuf[i+inOffset]);
	}
        
        public static void main(String[] argv) {
                
                System.out.println("testing StreamCipher");
                
 		byte[] k = new byte[KeySizeBytes];
		for(int i=0; i<KeySizeBytes; ++i)    k[i] = (byte)(i+2);
                
                byte[] nonce = new byte[StreamCipher.NonceSizeBytes];
                for (int i=0;i<StreamCipher.NonceSizeBytes;i++) nonce[i]=(byte)(i+3);
                
                StreamCipher sc = new StreamCipher(k);
                sc.setNonce(nonce);
                
                StreamCipher sc2 = new StreamCipher(k);
                sc2.setNonce(nonce);
                
                byte testByte = (byte) 0x56;
                System.out.println(testByte);
                byte cryptByte = sc.cryptByte(testByte);
                System.out.println(cryptByte);
                System.out.println(sc2.cryptByte(cryptByte));
        }
}
