package com.boomi.proserv.security.encrypting;

import com.boomi.mime.MimeUtils;
import com.boomi.proserv.security.KeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


public class SMIMEEncrypting implements Encrypting {

	public static final String PROVIDER = "BC";
	public static final String CHARSET_NAME = "utf-8";

	Session session;

	public SMIMEEncrypting() {
		try {
			Security.addProvider(new BouncyCastleProvider());
			session = Session.getDefaultInstance(System.getProperties(), null);
		} catch (Exception e){
			System.err.println("Error loading Provider, error" + e.getMessage()) ;
		}
	}

	@Override
	public String encrypt(String message, PublicKey publicKey, String algorithm) throws Exception {
		throw new Exception(this.getClass() + " requires the full Certificate Chain");
	}

	public String encrypt(String message, Certificate certificate, String algorithm) throws Exception {

		MimeMessage mimeMessage 	= new MimeMessage(session);
		mimeMessage.setText(message);

		MimeBodyPart msg 			= MimeUtils.createEncryptedMessage(
				mimeMessage,
				(X509Certificate) certificate,
				algorithm
		);

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		msg.writeTo(output);

		return output.toString(CHARSET_NAME);
	}

	public String decrypt(String message, PrivateKey privateKey, Certificate certificate, String algorithm) throws Exception {

		MimeBodyPart mimeBodyPart 		= new MimeBodyPart(KeyUtils.stringToInputStream(message));
		MimeBodyPart decryptedMessage 	= MimeUtils.getDecryptedMessage(
				(X509Certificate) certificate,
				privateKey,
				mimeBodyPart
		);
		return decryptedMessage.getContent().toString();
	}

	@Override
	public String decrypt(String message, PrivateKey privateKey, String algorithm) throws Exception {
		throw new Exception(this.getClass() + " requires the full Certificate Chain");
	}

}
