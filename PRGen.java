package p1;
import java.util.Random;

public class PRGen extends Random {
	// This implements a pseudorandom generator.  It extends java.util.Random, which provides
	//     a useful set of utility methods that all build on next(.).  See the documentation for
	//     java.util.Random for an explanation of what next(.) is supposed to do.
	// If you're calling a PRGen, you probably want to call methods of the Random superclass.
	//
	// There are two requirements on a pseudorandom generator.  First, it must be pseudorandom,
	//     meaning that there is no (known) way to distinguish its output from that of a
	//     truly random generator, unless you know the key.  Second, it must be deterministic, 
	//     which means that if two programs create generators with the same seed, and then
	//     the two programs make the same sequence of calls to their generators, they should
	//     receive the same return values from all of those calls.
	// Your generator must have an additional property: backtracking resistance.  This means that if an
	//     adversary is able to observe the full state of the generator at some point in time, that
	//     adversary cannot reconstruct any of the output that was produced by previous calls to the
	//     generator.

	private static final long serialVersionUID = 4210047820764873211L;
	
	public static final int KeySizeBytes = 32;   // IMPLEMENT THIS
	public static final int KeySizeBits = KeySizeBytes*8;
        private byte[] state;
        private byte[] zeroArray = new byte[KeySizeBytes];
        private byte[] oneArray = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
        

	public PRGen(byte[] key) {
		super();
		assert key.length == KeySizeBytes;
                zeroArray = new byte[KeySizeBytes];
                oneArray = new byte[KeySizeBytes];
                for (int i=0;i<KeySizeBytes;i++) {
                        zeroArray[i]=(byte)0x00;
                        oneArray[i]=(byte)0xff;
                }
                PRF prf = new PRF(key);
                state = prf.eval(key);
	}

	protected int next(int bits) {
		// For description of what this is supposed to do, see the documentation for 
		//      java.util.Random, which we are subclassing.
                advanceState();
                int bitmask = 0;
                for (int i=0; i<bits; i++) bitmask+=Math.pow(2, i);
                return (nextOutput() & bitmask);
	}
        
        private void advanceState() {
                PRF prf = new PRF(state);
                state = prf.eval(zeroArray);
        }
        
        private int nextOutput() {
                PRF prf = new PRF(state);
                byte[] output = prf.eval(oneArray);
                int outInt = 0;
                for (int i = 0; i <= 3; i++)
                        outInt = (outInt << 8) + (output[i] & 0xFF);
                return outInt;
        }
        
        public static void main(String[] argv) {
                System.out.println("testing PRGen");
		byte[] k = new byte[KeySizeBytes];
		for(int i=0; i<KeySizeBytes; ++i)    k[i] = (byte)(i+1);                
                PRGen prgen = new PRGen(k);
                for (int i=0; i<=32; i+=4)
                        System.out.println(prgen.next(i));   

	}
}