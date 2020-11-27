package com.boomi.proserv.security.encrypting;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface Encrypting {
	public String encrypt(String message, PublicKey publicKey, String algorithm) throws Exception;
	public String decrypt(String message, PrivateKey privateKey, String algorithm) throws Exception;
}
