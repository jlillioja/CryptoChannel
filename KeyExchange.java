package p2;

import java.math.BigInteger;

public class KeyExchange {
	public static final int OUTPUT_SIZE_BYTES = 256; // IMPLEMENT THIS
	public static final int OUTPUT_SIZE_BITS = 8 * OUTPUT_SIZE_BYTES;
        public BigInteger p = DHConstants.p;
        public BigInteger g = DHConstants.g;
        private BigInteger a;
        private int KeySize = 256;
        private PRGen random;

	public KeyExchange(PRGen rand) {
		// Prepares to do a key exchange. rand is a secure pseudorandom generator
		//    that can be used by the implementation.
		//
		// Once the KeyExchange object is created, two operations have to be performed to complete
		// the key exchange:
		// 1.  Call prepareOutMessage on this object, and send the result to the other
		//     participant.
		// 2.  Receive the result of the other participant's prepareOutMessage, and pass it in
		//     as the argument to a call on this object's processInMessage.  
		// For a given KeyExchange object, prepareOutMessage and processInMessage
		// could be called in either order, and KeyExchange should produce the same result regardless.
		//
		// The call to processInMessage should behave as follows:
		//     If passed a null value, then throw a NullPointerException.
		//     Otherwise, if passed a value that could not possibly have been generated
		//        by prepareOutMessage, then return null.
		//     Otherwise, return a "digest" value with the property described below.
		//
		// This code must provide the following security guarantee: If the two 
		//    participants end up with the same non-null digest value, then this digest value
		//    is not known to anyone else.   This must be true even if third parties
		//    can observe and modify the messages sent between the participants.
		// This code is NOT required to check whether the two participants end up with
		//    the same digest value; the code calling this must verify that property.

		// IMPLEMENT THIS
                //Standard p & q from RFC 51114 1024-bit MODP group
                //p = new BigInteger("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371");
                //g = new BigInteger("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5");
                //TODO: split into lines
				//didn't realize we had DHConstants
                byte[] ab = new byte[KeySize];
                rand.nextBytes(ab);
                a = Proj2Util.bytesToBigInteger(ab);
                random = rand;
	}

	public byte[] prepareOutMessage() {
		return Proj2Util.bigIntegerToBytes(g.modPow(a, p), OUTPUT_SIZE_BYTES); // IMPLEMENT THIS
	}

	public byte[] processInMessage(byte[] inMessage) {
		if (inMessage == null)    throw new NullPointerException();
                if (invalidMessage(inMessage)) return null;
                else return digest(inMessage);
	}

        private boolean invalidMessage(byte[] inMessage) {
                BigInteger messageValue = Proj2Util.bytesToBigInteger(inMessage);
                if (messageValue.equals(BigInteger.ONE)) return true;
                if (messageValue.equals(p.subtract(BigInteger.ONE))) return true;
                //if (messageValue.modPow(a, p) //TODO: how to determine if a message could not have possibly been generated by other party?
                else return false;
                
        }

        private byte[] digest(byte[] inMessage) { //Gross math
                return Proj2Util.hash(Proj2Util.bigIntegerToBytes(Proj2Util.bytesToBigInteger(inMessage).modPow(a, p), KeySize));
        }
}