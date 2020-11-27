package com.boomi.proserv.security.signing;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.JsonWebSignature;

public class JWSSigning implements Signing {

	public String sign(String message, PrivateKey privateKey, String algorithm) throws Exception {
	    JsonWebSignature jws = new JsonWebSignature();
	    jws.setPayload(message);
	    //See org.jose4j.jws.AlgorithmIdentifiers;
	    jws.setAlgorithmHeaderValue(algorithm);
	    jws.setKey(privateKey);
	    
	    return jws.getCompactSerialization();
	}
	
	public boolean validate(String message, String signature, PublicKey publicKey, String algorithm) throws Exception {
	    JsonWebSignature jws = new JsonWebSignature();

	    if(signature==null) {
	    	signature = message;
		}
	    jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, algorithm));
	    jws.setCompactSerialization(signature);
	    jws.setKey(publicKey);
	    
	    return jws.verifySignature();
	}
	
}
