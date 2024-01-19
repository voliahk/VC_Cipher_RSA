package rsa;

import java.math.BigInteger;
import java.util.EnumMap;
import java.util.Map;
import java.util.Random;

class VC_KeyPairGenerator {
	
	private Map<KEY_TYPES, VC_Key> LAST_KEYS = new EnumMap<KEY_TYPES, VC_Key>(KEY_TYPES.class);
	private int keySize = 512;

	public int getKeySize() {return keySize;}

	public void setKeySize(int keySize) {this.keySize = keySize;}
	
	private void setKeys(VC_Key publicKey, VC_Key privateKey) {
		LAST_KEYS.put(KEY_TYPES.PUBLIC_KEY, publicKey);
		LAST_KEYS.put(KEY_TYPES.PRIVATE_KEY, privateKey);
	}
	
	public VC_Key getPublicKey() {
		return LAST_KEYS.get(KEY_TYPES.PUBLIC_KEY);
	}
	
	public VC_Key getPrivateKey() {
		return LAST_KEYS.get(KEY_TYPES.PRIVATE_KEY);
	}
	
	public void calculateKeys() {
		BigInteger[] pairOfPQ = primeNumbers(); // {new BigInteger("19"), new BigInteger("41")};
		BigInteger n = theModulus(pairOfPQ[0], pairOfPQ[1]);
		BigInteger theEuler = eulerFunc(pairOfPQ[0], pairOfPQ[1]);
		BigInteger e = publicExponent(theEuler);
		BigInteger d = secretExponentRecoursive(theEuler,e)[1];
		VC_Key publicKey = new VC_Key(e, n, false);
		VC_Key privateKey = new VC_Key(d, n, true);
		setKeys(publicKey, privateKey);
//		BigInteger[][] keys = {{e,n},{d,n}};
//		return keys;
	}
	
	
	private BigInteger[] primeNumbers() {
		//вероятность составного 2^-100 
		BigInteger[] pairOfPQ = {BigInteger.probablePrime(this.keySize, new Random()), 
								BigInteger.probablePrime(this.keySize, new Random())};
		return pairOfPQ;
	}
	
	private BigInteger theModulus(BigInteger p, BigInteger q) {
		return p.multiply(q);
	}
	
	private BigInteger eulerFunc(BigInteger p,BigInteger  q) {
		p = p.subtract(new BigInteger("1"));
		q = q.subtract(new BigInteger("1"));
		return p.multiply(q);
	}
	
	private BigInteger publicExponent(BigInteger theEuler){
		String[] fermoNumbers = {"65537","257","17","5","3"}; 
		for(String fermo: fermoNumbers) {
			
			BigInteger e = theEuler;
			BigInteger publicExponent = new BigInteger(fermo);
			if(e.compareTo(publicExponent) < 0) {
				continue;
			}
			
			while(e.compareTo(BigInteger.ZERO) != 0 && publicExponent.compareTo(BigInteger.ZERO) != 0) {
				if(e.compareTo(publicExponent) > 0) {
					e = e.mod(publicExponent);
				}
				else {
					publicExponent = publicExponent.mod(e);
				}
			}
			e = e.add(publicExponent);
			if(e.compareTo(BigInteger.ONE) == 0)
				return new BigInteger(fermo);
		}
		return null;
	}
	
	private BigInteger[] secretExponentRecoursive(BigInteger a, BigInteger b) {
		if (b.compareTo(BigInteger.ZERO) == 0) {
			BigInteger[] bg = {BigInteger.ONE, BigInteger.ZERO};
			return bg;
		}
		BigInteger[] rec = secretExponentRecoursive(b, a.mod(b));
		BigInteger[] bg = {rec[1], rec[0].subtract(rec[1].multiply(a.divide(b)))};
		return bg;
	}
	
	//TODO неправильно работает - использовать secretExponentRecoursive
	private BigInteger secretExponent(BigInteger theEuler, BigInteger e) {
		BigInteger a = theEuler;
		BigInteger b = e;
		BigInteger q, r, x, y;
		BigInteger x1 = BigInteger.ZERO, y2 = BigInteger.ZERO;
		BigInteger y1 = BigInteger.ONE, x2 = BigInteger.ONE;
		
		while(b.compareTo(BigInteger.ZERO) > 0) {
			q = a.divide(b); // кратное 40 //6
			r = a.subtract(q.multiply(b)); //остаток //0//0
			x = x2.subtract(q.multiply(x1)); //-65337 //65337
			y = y2.subtract(q.multiply(y1)); //+... //-...
			a = b; // 1 //1
			b = r; // 0 //0
			x2 = x1; //1620 //-10700
			x1 = x; //-65337 //65337
			y2 = y1; //-... //
			y1 = y;
			if(b.compareTo(BigInteger.ZERO) == 0) {
				System.out.print("");
			}
		}
		if(x2.compareTo(y2) > 0) {
			return theEuler.subtract(y2.abs());
		}
		return theEuler.subtract(x2.abs());
	}	
}
