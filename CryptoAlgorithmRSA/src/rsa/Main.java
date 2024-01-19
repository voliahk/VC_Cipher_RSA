package rsa;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

public class Main {

	public static void main(String[] args) {
		
		VC_KeyPairGenerator kpg = new VC_KeyPairGenerator();
		kpg.setKeySize(512);
		kpg.calculateKeys();
		
		VC_Key publicKey = kpg.getPublicKey();
		VC_Key privateKey = kpg.getPrivateKey();
		System.out.println(publicKey.getExponent() + " " + publicKey.getModulus());
		System.out.println(privateKey.getExponent() + " " + privateKey.getModulus());
		
		VC_Cipher cipher = new VC_Cipher();
		
		String message = "The message";
		System.out.println(message);
		
		byte[] enc = cipher.encrypt(message.getBytes(), publicKey);
		enc = cipher.encrypt(enc, privateKey);
		System.out.println(new String(enc));
		
		VC_ElectronicSignature es = new VC_ElectronicSignature();
		HashMap<String, BigInteger> messageWithSign = es.signTheMessage(message.getBytes(), privateKey);
		System.out.println(messageWithSign);
		//message = "Aboba asdmlkm mlmlasdm sdfskdmwafk abir";
		System.out.println(es.authenticateSignature(messageWithSign, publicKey));
		
//		MessageDigest digest;
//		try {
//			digest = MessageDigest.getInstance("SHA-256");
//			byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
//			byte[] hash1 = digest.digest(message.getBytes(StandardCharsets.UTF_8));
//			System.out.println(Arrays.equals(hash, hash1));
//			System.out.println(Base64.getEncoder().encodeToString(hash));
//			System.out.println(Base64.getEncoder().encodeToString(hash1));
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
	}
}
