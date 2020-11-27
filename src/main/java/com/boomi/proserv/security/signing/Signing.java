package com.boomi.proserv.security.signing;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface Signing {
	public String sign(String message, PrivateKey privateKey, String algorithm) throws Exception;
	public boolean validate(String message, String signature, PublicKey publicKey, String algorithm) throws Exception;
}
