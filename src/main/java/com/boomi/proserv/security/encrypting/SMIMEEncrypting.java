package com.boomi.proserv.security.encrypting;

import com.boomi.proserv.security.KeyUtils;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;

public class SMIMEEncrypting implements Encrypting {

	public String encrypt(String message, PublicKey publicKey, String algorithm) throws Exception {
		/*

		See https://github.com/bcgit/bc-java/blob/master/mail/src/main/java/org/bouncycastle/mail/smime/examples/SendSignedAndEncryptedMail.java

		SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
		X509Certificate certificate = null;
		encrypter.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(certificate).setProvider("BC"));
		MimeBodyPart encryptedPart = encrypter.generate(
				message,
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC).setProvider("BC").build()
		);
		encryptedPart.getContent();

		return KeyUtils.encodeToBase64(cipher.doFinal(message.getBytes()));
		*/
		return null;
	}
	
	public String decrypt(String message, PrivateKey privateKey, String algorithm) throws Exception {
		return null;
	}
	
}
