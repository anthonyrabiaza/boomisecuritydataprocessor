package com.boomi.proserv.security.signing;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import com.boomi.proserv.security.KeyUtils;

/**
 * Signing X509Signing
 * @author anthony.rabiaza@gmail.com
 *
 */
public class X509Signing implements Signing {

	public String sign(String message, PrivateKey privateKey, String algorithm) throws Exception {
		Signature sign = Signature.getInstance(algorithm);
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		
		byte[] signature = sign.sign();
		
		return KeyUtils.encodeToBase64(signature);
	}
	
	public boolean validate(String message, String signature, PublicKey publicKey, String algorithm) throws Exception {
		Signature sign = Signature.getInstance(algorithm);
		sign.initVerify(publicKey);
		sign.update(message.getBytes());
		
		return sign.verify(KeyUtils.decodeBase64(signature));
	}
	
}
