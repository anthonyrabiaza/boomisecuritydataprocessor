package com.boomi.proserv.security.encrypting;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.boomi.proserv.security.TestSecurityHelper;

class X509EncryptingTest {

	@Test
	void test() throws Exception {
		X509Encrypting encrypting = new X509Encrypting();
		
		System.out.println("Loading message...");
		String message 	= "This is my message";
		System.out.println(">Message: " + message);
		assertNotNull("Message not null", message);
		
		String messageEncrypted = encrypting.encrypt(message, TestSecurityHelper.getPublicKey(), "RSA/ECB/PKCS1Padding");
		System.out.println(">Message Encrypted: " + messageEncrypted);
		
		String messageRecovered = encrypting.decrypt(messageEncrypted, TestSecurityHelper.getPrivateKey(), "RSA/ECB/PKCS1Padding");
		System.out.println(">Message decrypted: " + messageRecovered);
		
		assertEquals(message, messageRecovered);
	}

	@Test
	void testPassword() throws Exception {
		X509Encrypting encrypting = new X509Encrypting();

		System.out.println("Loading password...");
		String message 	= "!password123#";
		System.out.println(">Password: " + message);
		assertNotNull("Password not null", message);

		String messageEncrypted = encrypting.encrypt(message, TestSecurityHelper.getPublicKey(), "RSA/ECB/PKCS1Padding");
		System.out.println(">Password Encrypted: " + messageEncrypted);

		String messageRecovered = encrypting.decrypt(messageEncrypted, TestSecurityHelper.getPrivateKey(), "RSA/ECB/PKCS1Padding");
		System.out.println(">Password decrypted: " + messageRecovered);

		assertEquals(message, messageRecovered);
	}

	@Test
	void testWithSalt() throws Exception {
		X509Encrypting encrypting = new X509Encrypting();

		System.out.println("Loading message...");
		String message 	= "This is my message";
		System.out.println(">Message: " + message);
		assertNotNull("Message not null", message);

		int salt = 8;

		String messageEncrypted = encrypting.encrypt(message, salt, TestSecurityHelper.getPublicKey(), "RSA/ECB/PKCS1Padding");
		System.out.println(">Message Encrypted: " + messageEncrypted);

		String messageRecovered = encrypting.decrypt(messageEncrypted, salt, TestSecurityHelper.getPrivateKey(), "RSA/ECB/PKCS1Padding");
		System.out.println(">Message decrypted: " + messageRecovered);

		assertEquals(message, messageRecovered);
	}

}
