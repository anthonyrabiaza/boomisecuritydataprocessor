package com.boomi.proserv.security.encrypting;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.boomi.proserv.security.TestSecurityHelper;

class JWEEncryptingTest {

	@Test
	void testWithSecret() throws Exception {
		JWEEncrypting encrypting = new JWEEncrypting();
		String message = "This message is encrypted";

	    // The shared secret or shared symmetric key represented as a octet sequence JSON Web Key (JWK)
	    String secret = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
	    
	    String messageEncrypted = encrypting.encrypt(message, secret, "dir", "A128CBC-HS256");
	    System.out.println("Message encrypted: " + messageEncrypted);
	    
	    String messageRecovered = encrypting.decrypt(messageEncrypted, secret, "dir", "A128CBC-HS256");
	    System.out.println("Message decrypted: " + messageRecovered);
	    
	    assertEquals(message, messageRecovered);
	}
	
	@Test
	void test_RSA_OAEP_with_A256GCM() throws Exception {
		JWEEncrypting encrypting = new JWEEncrypting();
		String message = "Hello, this is a test";

	    String messageEncrypted = encrypting.encrypt(message, TestSecurityHelper.getPublicKey(), "RSA-OAEP", "A256GCM");
	    System.out.println("Message encrypted: " + messageEncrypted);
	    
	    String messageRecovered = encrypting.decrypt(messageEncrypted, TestSecurityHelper.getPrivateKey(), "RSA-OAEP", "A256GCM");
	    System.out.println("Message decrypted: " + messageRecovered);
	    
	    assertEquals(message, messageRecovered);
	}

}
