package com.boomi.proserv.security.signing;

import com.boomi.proserv.security.TestSecurityHelper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWSSigningTest {

	@Test
	void test() throws Exception {
		Signing signing		= new JWSSigning();
		String message 		= "This is the message to sign";
		String algorithm 	= "RS256";
		String signature 	= signing.sign(message, TestSecurityHelper.getPrivateKey(), algorithm);
		assertNotNull(signature, "Signature not null");
		boolean signatureValid = signing.validate(signature, null, TestSecurityHelper.getPublicKey(), algorithm);
		assertTrue(signatureValid, "Signature is valid");
	}

}
