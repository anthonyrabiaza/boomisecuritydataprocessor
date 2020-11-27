package com.boomi.proserv.security.signing;

import com.boomi.proserv.security.TestSecurityHelper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class X509SigningTest {

	@Test
	void test() throws Exception {
		Signing signing		= new X509Signing();
		String message 		= "This is the message to sign";
		String algorithm 	= "SHA256withRSA";
		String signature 	= signing.sign(message, TestSecurityHelper.getPrivateKey(), algorithm);
		assertNotNull(signature, "Signature not null");
		boolean signatureValid = signing.validate(message, signature, TestSecurityHelper.getPublicKey(), algorithm);
		assertTrue(signatureValid, "Signature is valid");
	}

}
