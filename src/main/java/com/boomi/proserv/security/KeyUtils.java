package com.boomi.proserv.security;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * KeyUtils class
 * @author anthony.rabiaza@gmail.com
 *
 */
public class KeyUtils {

	/**
	 * Load Private key with .p12/.pfx extension (in PKCS12 format)
	 * @param filename
	 * @param alias
	 * @param password
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey loadPrivateKey(String filename, String alias, String password) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(filename), password.toCharArray());
		return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
	}
	
	/**
	 * Load Public key with .p12/.pfx extension (in PKCS12 format) or with .cer/.crt extension
	 * @param filename
	 * @param alias
	 * @param password
	 * @return
	 * @throws Exception
	 */
	public static PublicKey loadPublicKey(String filename, String alias, String password) throws Exception {
		if(filename.toLowerCase().endsWith(".p12") || filename.toLowerCase().endsWith(".pfx")) {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(new FileInputStream(filename), password.toCharArray());
			Certificate certificate = keyStore.getCertificate(alias);
			return certificate.getPublicKey();
		} else {
			FileInputStream fr = new FileInputStream(filename); 
			CertificateFactory cf = CertificateFactory.getInstance("X509"); 
			X509Certificate cert = (X509Certificate) cf.generateCertificate(fr);
			return cert.getPublicKey();
		}
	}
	
	public static void showSecurityProviders() {
		Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			System.out.println(providers[i]);
		}
	}
	
	public static String encodeToBase64(byte[] b) {
		return new String(Base64.getEncoder().encode(b));
	}
	
	public static String decodeBase64(byte[] b) {
		return new String(Base64.getDecoder().decode(b));
	}
	
	public static byte[] decodeBase64(String str) {
		return Base64.getDecoder().decode(str);
	}
	
	//	public static PrivateKey loadPrivateKey(String filename) throws Exception {
	//		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
	//		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	//		KeyFactory kf = KeyFactory.getInstance("RSA");
	//		return kf.generatePrivate(spec);
	//	}

	public static String generateSecureString(int length) throws Exception {
		String chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		SecureRandom secureRandom = SecureRandom.getInstanceStrong();
		String secureString = secureRandom.ints(length, 0, chars.length()).mapToObj(i -> chars.charAt(i))
				.collect(StringBuilder::new, StringBuilder::append, StringBuilder::append).toString();
		return secureString;
	}
}
