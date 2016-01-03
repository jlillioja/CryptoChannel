package p2;

import java.math.BigInteger;
import java.util.Arrays;

public class RSAKeyPair {
	private RSAKey publicKey;
	private RSAKey privateKey;
        private BigInteger p;
        private BigInteger q;

	public RSAKeyPair(PRGen rand, int numBits) {
		// Create an RSA key pair.  rand is a PRGen that this code can use to get pseudorandom
		//     bits.  numBits is the size in bits of each of the primes that will be used.
                p = Proj2Util.generatePrime(rand, numBits);
                q = Proj2Util.generatePrime(rand, numBits);
                BigInteger mod = p.multiply(q);
                BigInteger[] exponents = calcExponents(p, q);
                
                publicKey = new RSAKey(exponents[0], mod);
                privateKey = new RSAKey(exponents[1], mod);
	}

	public RSAKey getPublicKey() {
		return publicKey;
	}

	public RSAKey getPrivateKey() {
		return privateKey;
	}

	public BigInteger[] getPrimes(PRGen rand, int numBits) {
		// Returns an array containing the two primes that were used in key generation.
		//   In real life we don't always keep the primes around.
		//   But including this helps us grade the assignment.
		BigInteger[] ret = new BigInteger[2];
		ret[0] = p;
		ret[1] = q;
		return ret;
	}

        private BigInteger[] calcExponents(BigInteger p, BigInteger q) {
                BigInteger totient = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
                BigInteger e;
                BigInteger d;
                //e = BigInteger.valueOf(2^8);
                e = new BigInteger("65537");
                while (((totient.gcd(e)).compareTo(BigInteger.ONE) != 0)) { //If gcd(e,totient) != 1
                        e = e.nextProbablePrime();                          //Look for another e
                }
                d = e.modInverse(totient);
                if (BigInteger.ONE.compareTo(e.multiply(d).mod(totient)) != 0) {
                        System.out.println("KEY PAIR NOT INVERSES");
                        System.exit(0);
                }
                BigInteger[] exponents = new BigInteger[2];                
                exponents[0] = e;
                exponents[1] = d;
                System.out.println(Arrays.toString(exponents));
                return exponents;
        }
        
        public static void main(String[] argv) {
                byte [] initKey = new byte[128];
                byte[] plaintext = {0x1, 0x2, 0x3, 0x4};
                for (int i=0;i<128;i++) initKey[i] = (byte) (i%(2^8));
                PRGen prgen = new PRGen(initKey);
                RSAKeyPair keys = new RSAKeyPair(prgen, 384);
                
                System.out.print("Plaintext1: "); System.out.println(Arrays.toString(plaintext));
                byte[] decryptedPlaintext1 = keys.publicKey.RSACrypt(keys.privateKey.RSACrypt(plaintext));
                System.out.print("decryptedPlaintext1: "); System.out.println(Arrays.toString(decryptedPlaintext1));
                
                System.out.print("Plaintext2: "); System.out.println(Arrays.toString(plaintext));
                byte[] decryptedPlaintext2 = keys.publicKey.removePadding(keys.publicKey.RSACrypt(keys.privateKey.RSACrypt(keys.privateKey.addPadding(plaintext))));
                System.out.print("Decrypted Plaintext2: "); System.out.println(Arrays.toString(decryptedPlaintext2));
                
                
                System.out.print("Plaintext3: "); System.out.println(Arrays.toString(plaintext));
                byte[] decryptedPlaintext3 = keys.publicKey.decrypt(keys.privateKey.encrypt(plaintext, prgen));
                System.out.print("decryptedPlaintext3: "); System.out.println(Arrays.toString(decryptedPlaintext3));
                
        }
}
