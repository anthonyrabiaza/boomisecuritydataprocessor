package com.boomi.proserv.security;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestSecurityHelper {

	public static PrivateKey getPrivateKey() throws Exception {
		return getPrivateKey("src/test/boomi.pfx");
	}
	public static PrivateKey getPrivateKey(String filename) throws Exception {
		System.out.println("Loading private key...");
		PrivateKey privateKey = KeyUtils.loadPrivateKey(
				filename,
				"1",
				"changeit"
		);
		System.out.println(">Loaded");
		return privateKey;
	}

	public static PublicKey getPublicKey() throws Exception {
		return getPublicKey("src/test/boomi.cer");
	}

	public static PublicKey getPublicKey(String filename) throws Exception {
		System.out.println("Loading public key...");
		PublicKey publicKey = KeyUtils.loadPublicKey(
			filename,
			"1",
			""
		);
		System.out.println(">Loaded");
		return publicKey;
	}

	public static Certificate getCertificate() throws Exception {
		return KeyUtils.getCertificate("src/test/boomi.cer", "1", "");
	}

	@Test
	void test() {
		assertTrue(true, "basic validation");
	}
}
