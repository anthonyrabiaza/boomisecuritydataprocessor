package com.boomi.proserv.security.encrypting;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import com.boomi.proserv.security.KeyUtils;

public class X509Encrypting implements Encrypting {

	public String encrypt(String message, PublicKey publicKey, String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return KeyUtils.encodeToBase64(cipher.doFinal(message.getBytes()));
	}

	public String encrypt(String message, int salt, PublicKey publicKey, String algorithm) throws Exception {
		if(salt==0) {
			return encrypt(message, publicKey, algorithm);
		} else {
			String saltString = KeyUtils.generateSecureString(salt);
			return encrypt(saltString.concat(message), publicKey, algorithm);
		}
	}
	
	public String decrypt(String message, PrivateKey privateKey, String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(KeyUtils.decodeBase64(message)));
	}

	public String decrypt(String message, int salt, PrivateKey privateKey, String algorithm) throws Exception {
		if(salt==0) {
			return decrypt(message, privateKey, algorithm);
		} else {
			String decryptedString =  decrypt(message, privateKey, algorithm);
			return decryptedString.substring(salt, decryptedString.length());
		}
	}
	
}
