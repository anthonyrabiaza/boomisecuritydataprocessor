package com.boomi.proserv.security.encrypting;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;

public class JWEEncrypting implements Encrypting {
	
	@Override
	public String encrypt(String message, PublicKey publickey, String algorithm) throws Exception {
		return encrypt(message, publickey, KeyManagementAlgorithmIdentifiers.DIRECT, algorithm);
	}

	public String encrypt(String message, String secret, String algorithmHeader, String algorithm) throws Exception {
		JsonWebKey jwk = JsonWebKey.Factory.newJwk(secret);
		
		return encrypt(message, jwk.getKey(), algorithmHeader, algorithm);
	}
	
	public String encrypt(String message, Key key, String algorithmHeader, String algorithm) throws Exception {
	    JsonWebEncryption senderJwe = new JsonWebEncryption();
	    senderJwe.setPlaintext(message);
	    senderJwe.setAlgorithmHeaderValue(algorithmHeader);
	    senderJwe.setEncryptionMethodHeaderParameter(algorithm);
	    senderJwe.setKey(key);
	    
	    return senderJwe.getCompactSerialization();
	}
	
	@Override
	public String decrypt(String message, PrivateKey privatekey, String algorithm) throws Exception {
		return decrypt(message, privatekey, KeyManagementAlgorithmIdentifiers.DIRECT, algorithm);
	}
	
	public String decrypt(String message, String secret, String algorithmHeader, String algorithm) throws Exception {
		JsonWebKey jwk = JsonWebKey.Factory.newJwk(secret);
		
		return decrypt(message, jwk.getKey(), algorithmHeader, algorithm);
	}
	
	public String decrypt(String message, Key key, String algorithmHeader, String algorithm) throws Exception {
	    JsonWebEncryption receiverJwe = new JsonWebEncryption();
	    AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.PERMIT, algorithmHeader);
	    receiverJwe.setAlgorithmConstraints(algConstraints);
	    AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.PERMIT, algorithm);
	    receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);
	    receiverJwe.setCompactSerialization(message);
	    receiverJwe.setKey(key);

	    return receiverJwe.getPlaintextString();
	}
	
}
