package rsa;

import java.math.BigInteger;

class VC_Key {

	private BigInteger exponent;
	private BigInteger modulus;
	private boolean isPrivate;
	
	VC_Key(BigInteger exponent, BigInteger modulus, boolean isPrivate){
		this.exponent = exponent;
		this.modulus = modulus;
		this.isPrivate = isPrivate;
	}
	
	public BigInteger[] getKey() {
		BigInteger[] key = {this.exponent, this.modulus};
		return key;
	}
	
	public BigInteger getExponent() {
		return this.exponent;
	}
	
	public BigInteger getModulus() {
		return this.modulus;
	}

	public boolean isPrivate() {
		return isPrivate;
	}
}
