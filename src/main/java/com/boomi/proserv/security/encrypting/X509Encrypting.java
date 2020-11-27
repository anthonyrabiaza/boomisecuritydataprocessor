package com.boomi.proserv.security.encrypting;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import com.boomi.proserv.security.KeyUtils;

public class X509Encrypting implements Encrypting {

	public String encrypt(String message, PublicKey publicKey, String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return KeyUtils.encodeToBase64(cipher.doFinal(message.getBytes()));
	}
	
	public String decrypt(String message, PrivateKey privateKey, String algorithm) throws Exception {
		Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(KeyUtils.decodeBase64(message)));
	}
	
}
