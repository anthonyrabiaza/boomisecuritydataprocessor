package com.boomi.proserv.security.encrypting;

import com.boomi.proserv.security.TestSecurityHelper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SMIMEEncryptingTest {

	@Test
	void test() throws Exception {
		SMIMEEncrypting encrypting = new SMIMEEncrypting();
		
		System.out.println("Loading message...");
		String message 	= "This is my message";
		System.out.println(">Message: " + message);
		assertNotNull("Message not null", message);

		String from 	= "anthony.rabiaza@boomi.com";
		String to 		= "smime@abigbank.com";
		String subject	= "Subject of the message";
		
		String messageEncrypted = encrypting.encrypt(message, from, to, subject, TestSecurityHelper.getCertificate(), "RC2_CBC");
		System.out.println(">Message Encrypted: " + messageEncrypted);
		
		String messageRecovered = encrypting.decrypt(messageEncrypted, TestSecurityHelper.getPrivateKey(), TestSecurityHelper.getCertificate(),"RC2");
		System.out.println(">Message decrypted: " + messageRecovered);
		
		assertEquals(message, messageRecovered);
	}

}
