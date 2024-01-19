package rsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;


class VC_ElectronicSignature {

	public HashMap<String, BigInteger> signTheMessage(byte[] message, VC_Key privateKey) {
		if(!privateKey.isPrivate()) {
			return null;
		}
		
		HashMap<String, BigInteger> messageWithSign = new HashMap<>();
		byte[] hashMessage;
		BigInteger electronicSign;
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hashMessage = digest.digest(message);
			BigInteger binaryMessage = new BigInteger(hashMessage);
			electronicSign = binaryMessage.modPow(privateKey.getExponent(), privateKey.getModulus());
			messageWithSign.put(Base64.getEncoder().encodeToString(hashMessage), electronicSign);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return messageWithSign;
	}
	
	public boolean authenticateSignature(HashMap<String, BigInteger> messageWithSign, VC_Key publicKey, byte[] message) {
		byte[] hashMessage;
		byte[] hashOfReceivedMessage;
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hashMessage = digest.digest(message);
			for (HashMap.Entry<String, BigInteger> entry : messageWithSign.entrySet()) {
				BigInteger binaryMessage = entry.getValue().modPow(publicKey.getExponent(), publicKey.getModulus());
				hashOfReceivedMessage = binaryMessage.toByteArray();
				return Arrays.equals(hashMessage, hashOfReceivedMessage);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
}
