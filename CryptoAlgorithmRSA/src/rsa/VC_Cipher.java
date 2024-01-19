package rsa;

import java.math.BigInteger;

class VC_Cipher {
	
	public byte[] encrypt(byte[] message, VC_Key key) {
		BigInteger binaryMessage = new BigInteger(message);
		BigInteger encryptedMessage = binaryMessage.modPow(key.getExponent(), key.getModulus());
		return encryptedMessage.toByteArray();
	}
	
}
