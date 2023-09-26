package com.boomi.proserv.security;

import com.boomi.proserv.security.pgp.PGPKeyUtils;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.InputStream;
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

	public static PGPSecretKey getMyPGPPrivateKey() throws Exception {
		System.out.println("Loading own pgp private key...");
		return getPGPPrivateKey("src/test/pgp-boomi-priv.asc");
	}

	public static PGPSecretKey getEntityPGPPrivateKey() throws Exception {
		System.out.println("Loading other entity pgp private key...");
		return getPGPPrivateKey("src/test/pgp-companyxyz-priv.asc");
	}
	public static PGPSecretKey getPGPPrivateKey(String filename) throws Exception {
		// Load private key from file
		InputStream privateKeyringInputStream = new FileInputStream(filename);
		// Get signing key
		PGPSecretKey pgpSecretKey = null; //FIXME
		//PGPSecretKey pgpSecretKey = PGPKeyUtils.getPGPPrivateKey(privateKeyringInputStream);
		System.out.println(">Loaded");
		return pgpSecretKey;
	}

	public static PGPPublicKey getMyPGPPublicKey() throws Exception {
		System.out.println("Loading own pgp public key...");
		return getPGPPublicKey("src/test/pgp-boomi-pub.asc");
	}

	public static PGPPublicKey getEntityPGPPublicKey() throws Exception {
		System.out.println("Loading other entity pgp public key...");
		return getPGPPublicKey("src/test/pgp-companyxyz-pub.asc");
	}

	public static PGPPublicKey getPGPPublicKey(String filename) throws Exception {
		// Load public key from file
		InputStream publicKeyringInputStream = new FileInputStream(filename);
		// Get public key
		PGPPublicKey pgpPublicKey = null;//FIXME
		//PGPPublicKey pgpPublicKey = PGPKeyUtils.getPGPPublicKey(publicKeyringInputStream);
		System.out.println(">Loaded");
		return pgpPublicKey;
	}

	public static Certificate getCertificate() throws Exception {
		return KeyUtils.getCertificate("src/test/boomi.cer", "1", "");
	}

	@Test
	void test() {
		assertTrue(true, "basic validation");
	}
}
