package com.boomi.proserv.security.encrypting;

import com.boomi.proserv.security.KeyUtils;
import net.markenwerk.utils.mail.smime.SmimeKey;
import net.markenwerk.utils.mail.smime.SmimeState;
import net.markenwerk.utils.mail.smime.SmimeUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
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
			session 	= Session.getDefaultInstance(System.getProperties(), null);
		} catch (Exception e){
			System.err.println("Error loading Provider, error" + e.getMessage()) ;
		}
	}

	@Override
	public String encrypt(String message, PublicKey publicKey, String algorithm) throws Exception {
		throw new Exception(this.getClass() + " requires the full Certificate Chain");
	}

	public String encrypt(String message, String from, String to, String subject, Certificate certificate, String algorithm) throws Exception {

		SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();
		gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator((X509Certificate)certificate).setProvider(PROVIDER));//WORKING

		MimeBodyPart    msg 		= new MimeBodyPart();
		msg.setText(message);
		MimeBodyPart mp = gen.generate(msg, new JceCMSContentEncryptorBuilder(getAlgorithm(algorithm)).setProvider(PROVIDER).build());

		Address fromUser 			= new InternetAddress(from);
		Address toUser 				= new InternetAddress(to);

		MimeMessage body 			= new MimeMessage(session);
		body.setFrom(fromUser);
		body.setRecipient(Message.RecipientType.TO, toUser);
		body.setSubject(subject);
		body.setContent(mp.getContent(), mp.getContentType());
		body.saveChanges();

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		body.writeTo(output);

		return output.toString(CHARSET_NAME);
	}

	public String decrypt(String message, PrivateKey privateKey, Certificate certificate, String algorithm) throws Exception {

		MimeMessage mimeMessage 		= new MimeMessage(session, KeyUtils.stringToInputStream(message));
		SmimeState smimeState 			= SmimeUtil.getStatus(mimeMessage);
		if(smimeState.equals(SmimeState.ENCRYPTED)) {
			SmimeKey mimeKey = new SmimeKey(privateKey, (X509Certificate) certificate);
			MimeMessage decryptedMessage = SmimeUtil.decrypt(session, mimeMessage, mimeKey);
			return KeyUtils.inputStreamToString(decryptedMessage.getInputStream());
		} else {
			throw new Exception("Message has a " + smimeState + " state");
		}
	}

	@Override
	public String decrypt(String message, PrivateKey privateKey, String algorithm) throws Exception {
		throw new Exception(this.getClass() + " requires the full Certificate Chain");
	}

	private ASN1ObjectIdentifier getAlgorithm(String algorithm) {

		ASN1ObjectIdentifier identifier;
		switch (algorithm) {
			case "DES_CBC": identifier = CMSAlgorithm.DES_CBC; break;
			case "DES_EDE3_CBC": identifier = CMSAlgorithm.DES_EDE3_CBC; break;
			case "RC2_CBC": identifier = CMSAlgorithm.RC2_CBC; break;
			case "IDEA_CBC": identifier = CMSAlgorithm.IDEA_CBC; break;
			case "CAST5_CBC": identifier = CMSAlgorithm.CAST5_CBC; break;
			case "AES128_CBC": identifier = CMSAlgorithm.AES128_CBC; break;
			case "AES192_CBC": identifier = CMSAlgorithm.AES192_CBC; break;
			case "AES256_CBC": identifier = CMSAlgorithm.AES256_CBC; break;
			case "AES128_CCM": identifier = CMSAlgorithm.AES128_CCM; break;
			case "AES192_CCM": identifier = CMSAlgorithm.AES192_CCM; break;
			case "AES256_CCM": identifier = CMSAlgorithm.AES256_CCM; break;
			case "AES128_GCM": identifier = CMSAlgorithm.AES128_GCM; break;
			case "AES192_GCM": identifier = CMSAlgorithm.AES192_GCM; break;
			case "AES256_GCM": identifier = CMSAlgorithm.AES256_GCM; break;
			case "CAMELLIA128_CBC": identifier = CMSAlgorithm.CAMELLIA128_CBC; break;
			case "CAMELLIA192_CBC": identifier = CMSAlgorithm.CAMELLIA192_CBC; break;
			case "CAMELLIA256_CBC": identifier = CMSAlgorithm.CAMELLIA256_CBC; break;
			case "SEED_CBC": identifier = CMSAlgorithm.SEED_CBC; break;
			case "DES_EDE3_WRAP": identifier = CMSAlgorithm.DES_EDE3_WRAP; break;
			case "AES128_WRAP": identifier = CMSAlgorithm.AES128_WRAP; break;
			case "AES192_WRAP": identifier = CMSAlgorithm.AES192_WRAP; break;
			case "AES256_WRAP": identifier = CMSAlgorithm.AES256_WRAP; break;
			case "CAMELLIA128_WRAP": identifier = CMSAlgorithm.CAMELLIA128_WRAP; break;
			case "CAMELLIA192_WRAP": identifier = CMSAlgorithm.CAMELLIA192_WRAP; break;
			case "CAMELLIA256_WRAP": identifier = CMSAlgorithm.CAMELLIA256_WRAP; break;
			case "SEED_WRAP": identifier = CMSAlgorithm.SEED_WRAP; break;
			case "ECDH_SHA1KDF": identifier = CMSAlgorithm.ECDH_SHA1KDF; break;
			case "ECCDH_SHA1KDF": identifier = CMSAlgorithm.ECCDH_SHA1KDF; break;
			case "ECMQV_SHA1KDF": identifier = CMSAlgorithm.ECMQV_SHA1KDF; break;
			case "ECDH_SHA224KDF": identifier = CMSAlgorithm.ECDH_SHA224KDF; break;
			case "ECCDH_SHA224KDF": identifier = CMSAlgorithm.ECCDH_SHA224KDF; break;
			case "ECMQV_SHA224KDF": identifier = CMSAlgorithm.ECMQV_SHA224KDF; break;
			case "ECDH_SHA256KDF": identifier = CMSAlgorithm.ECDH_SHA256KDF; break;
			case "ECCDH_SHA256KDF": identifier = CMSAlgorithm.ECCDH_SHA256KDF; break;
			case "ECMQV_SHA256KDF": identifier = CMSAlgorithm.ECMQV_SHA256KDF; break;
			case "ECDH_SHA384KDF": identifier = CMSAlgorithm.ECDH_SHA384KDF; break;
			case "ECCDH_SHA384KDF": identifier = CMSAlgorithm.ECCDH_SHA384KDF; break;
			case "ECMQV_SHA384KDF": identifier = CMSAlgorithm.ECMQV_SHA384KDF; break;
			case "ECDH_SHA512KDF": identifier = CMSAlgorithm.ECDH_SHA512KDF; break;
			case "ECCDH_SHA512KDF": identifier = CMSAlgorithm.ECCDH_SHA512KDF; break;
			case "ECMQV_SHA512KDF": identifier = CMSAlgorithm.ECMQV_SHA512KDF; break;
			case "SHA1": identifier = CMSAlgorithm.SHA1; break;
			case "SHA224": identifier = CMSAlgorithm.SHA224; break;
			case "SHA256": identifier = CMSAlgorithm.SHA256; break;
			case "SHA384": identifier = CMSAlgorithm.SHA384; break;
			case "SHA512": identifier = CMSAlgorithm.SHA512; break;
			case "MD5": identifier = CMSAlgorithm.MD5; break;
			case "GOST3411": identifier = CMSAlgorithm.GOST3411; break;
			case "RIPEMD128": identifier = CMSAlgorithm.RIPEMD128; break;
			case "RIPEMD160": identifier = CMSAlgorithm.RIPEMD160; break;
			case "RIPEMD256": identifier = CMSAlgorithm.RIPEMD256; break;
			default: identifier = CMSAlgorithm.RC2_CBC;
		}
		//Default
		return identifier;
	}
}
