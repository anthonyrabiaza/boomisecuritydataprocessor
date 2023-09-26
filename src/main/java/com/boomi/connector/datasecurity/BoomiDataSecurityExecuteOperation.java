package com.boomi.connector.datasecurity;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.boomi.connector.api.ObjectData;
import com.boomi.connector.api.OperationResponse;
import com.boomi.connector.api.OperationStatus;
import com.boomi.connector.api.PrivateKeyStore;
import com.boomi.connector.api.PublicKeyStore;
import com.boomi.connector.api.ResponseUtil;
import com.boomi.connector.api.UpdateRequest;
import com.boomi.connector.util.BaseUpdateOperation;
import com.boomi.proserv.security.KeyUtils;
import com.boomi.proserv.security.encrypting.JWEEncrypting;
import com.boomi.proserv.security.encrypting.SMIMEEncrypting;
import com.boomi.proserv.security.encrypting.X509Encrypting;
import com.boomi.proserv.security.pgp.PGPKeyUtils;
import com.boomi.proserv.security.pgp.PGPSigning;
import com.boomi.proserv.security.pkce.CodeGenerator;
import com.boomi.proserv.security.signing.JWSSigning;
import com.boomi.proserv.security.signing.X509Signing;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * Execute the Operation, no profile need to be "imported" to the operation (as input are binaries)
 * @author Anthony Rabiaza 
 *
 */
public class BoomiDataSecurityExecuteOperation extends BaseUpdateOperation {

	protected BoomiDataSecurityExecuteOperation(BoomiDataSecurityConnection conn) {
		super(conn);
	}

	@Override
	protected void executeUpdate(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		String customOperationType = getContext().getCustomOperationType();

		if(customOperationType == null || customOperationType=="") {
			customOperationType = "default";
		}

		switch (customOperationType) {
			case "PGP":
				executeUpdatePGP(request, response);
				break;
			case "PKCE_CODE_VERIFIER":
				executeUpdatePKCECodeVerifier(request, response);
				break;
			case "PKCE_CODE_CHALLENGE":
				executeUpdatePKCECodeChallenge(request, response);
				break;
			case "default":
			default:
				executeUpdateStandard(request, response);
				break;
		}
	}

	protected void executeUpdateStandard(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateStandard received");

		String action 						= getContext().getOperationProperties().getProperty("action");
		String standard 					= getContext().getOperationProperties().getProperty("standard");
		String signingAlgorithm 			= getContext().getOperationProperties().getProperty("signingAlgorithm");
		String encryptingAlgorithm			= getContext().getOperationProperties().getProperty("encryptingAlgorithm");
		String encryptingAlgorithmHeader	= getContext().getOperationProperties().getProperty("encryptingAlgorithmHeader");
		String keyAlias						= getContext().getOperationProperties().getProperty("keyAlias");

		log(logger, log, "ARA: action is " + action + ", standard is " + standard 
				+ " signing algorith is " + signingAlgorithm + " and encryptingAlgorithm is " + encryptingAlgorithm);

		PrivateKey privateKey;
		PublicKey publicKey;
		Certificate certificate;
		String secret;
		String signature;
		String from;
		String to;
		String subject;
		
		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());
				String result  = "ERROR";

				if(message!=null) {
					try {
						switch(action) {
							case "sign":
								privateKey = getPrivateKey(keyAlias);
								switch(standard) {
									case "x509":
										result 	= new X509Signing().sign(message, privateKey, signingAlgorithm);
									break;
									case "jose":
										result 	= new JWSSigning().sign(message, privateKey, signingAlgorithm);
									break;
									default:
								}
							break;
							case "validateSignature":
								publicKey 	= getPublicKey(keyAlias);
								signature	= input.getDynamicProperties().get("signature");
								switch(standard) {
									case "x509":
										result = String.valueOf(new X509Signing().validate(message, signature, publicKey, signingAlgorithm));
									break;
									case "jose":
										result = String.valueOf(new JWSSigning().validate(message, signature, publicKey, signingAlgorithm));
									break;
									default:
								}
							break;
							case "encrypt":
								switch(standard) {
									case "x509":
										publicKey 		= getPublicKey(keyAlias);
										result 			= new X509Encrypting().encrypt(message, publicKey, encryptingAlgorithm);
									break;
									case "jose":
										secret = input.getDynamicProperties().get("secret");
										if(secret == null || "".equals(secret)) {
											publicKey 	= getPublicKey(keyAlias);
											result		= new JWEEncrypting().encrypt(message, publicKey, encryptingAlgorithmHeader, encryptingAlgorithm);
										} else {
											result		= new JWEEncrypting().encrypt(message, secret, encryptingAlgorithmHeader, encryptingAlgorithm);
										}
									break;
									case "s/mime":
										certificate = getCertificate(keyAlias);
										result		= new SMIMEEncrypting().encrypt(message, certificate, encryptingAlgorithm);
									break;
									default:
								}
							break;
							case "decrypt":
								switch(standard) {
									case "x509":
										privateKey 		= getPrivateKey(keyAlias);
										result 			= new X509Encrypting().decrypt(message, privateKey, encryptingAlgorithm);
									break;
									case "jose":
										secret = input.getDynamicProperties().get("secret");
										if(secret == null || "".equals(secret)) {
											privateKey 	= getPrivateKey(keyAlias);
											result		= new JWEEncrypting().decrypt(message, privateKey, encryptingAlgorithmHeader, encryptingAlgorithm);
										} else {

											result		= new JWEEncrypting().decrypt(message, secret, encryptingAlgorithmHeader, encryptingAlgorithm);
										}
									break;
									case "s/mime":
										certificate = getCertificate(input.getDynamicProperties().get("alias"));
										privateKey 	= getPrivateKey(keyAlias);
										result		= new SMIMEEncrypting().decrypt(message, privateKey, certificate, encryptingAlgorithm);
									break;
									default:
								}
							break;
							default:
						}

						response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(result));
					} catch (Exception e) {
						logger.severe(e.getMessage());
						e.printStackTrace();
						throw e;
					}
				}

				log(logger, log, "ARA: Document processed");

			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdatePGP(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdatePGP received");

		String action 					= getContext().getOperationProperties().getProperty("action");
		String hashingAlgorithm 		= getContext().getOperationProperties().getProperty("hashingAlgorithm");
		String compressionAlgorithm 	= getContext().getOperationProperties().getProperty("signingAlgorithm");
		String symmetricKeyAlgorithm	= getContext().getOperationProperties().getProperty("symmetricKeyAlgorithm");
		boolean applyIntegrityCheck		= getContext().getOperationProperties().getBooleanProperty("applyIntegrityCheck");

		log(logger, log, "ARA: action is " + action + ", hashingAlgorithm is " + hashingAlgorithm
				+ " compressionAlgorithm is " + compressionAlgorithm + " encryptingAlgorithm is " + symmetricKeyAlgorithm
				+ " and applyIntegrityCheck is " + applyIntegrityCheck
		);

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());
				String result = "ERROR";

				if (message != null) {
					try {
						switch (action) {
							case "sign":
								String keyPassphrase 		= input.getDynamicProperties().get("keyPassphrase");
								String pgpPrivateKeyContent = input.getDynamicProperties().get("pgpPrivateKey");
								//PGPSecretKey pgpPrivateKey 	= PGPKeyUtils.getPGPPrivateKey(KeyUtils.stringToInputStream(pgpPrivateKeyContent));
								result = null;
								//result = new PGPSigning().sign(message, pgpPrivateKey, keyPassphrase, Integer.parseInt(hashingAlgorithm), Integer.parseInt(compressionAlgorithm));
								break;
							case "signAndEncrypt":
								break;
							case "validateSignature":
								break;
							case "encrypt":
								break;
							case "decrypt":
								break;
						}

						response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(result));
					} catch (Exception e) {
						logger.severe(e.getMessage());
						e.printStackTrace();
						throw e;
					}

				}

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdatePKCECodeVerifier(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdatePKCECodeVerifier received");

		for (ObjectData input : request) {
			try {
				log(logger, log, "ARA: Processing document ...");

				String result = "ERROR";

				result = CodeGenerator.generateCodeVerifier();
				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(result));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdatePKCECodeChallenge(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdatePKCECodeChallenge received");

		String algorithm 		= getContext().getOperationProperties().getProperty("algorithm");

		log(logger, log, "ARA: algorithm is " + algorithm);

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());
				String result = "ERROR";

				if (message != null) {
					try {
						CodeGenerator.generateCodeChallenge(message, algorithm);

						response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(result));
					} catch (Exception e) {
						logger.severe(e.getMessage());
						e.printStackTrace();
						throw e;
					}

				}

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	private Certificate getCertificate(String keyAlias) throws Exception {
		PublicKeyStore publickeyStore;
		PublicKey publicKey;
		Certificate certificate;
		publickeyStore 	= getContext().getConnectionProperties().getPublicKeyStoreProperty("publicKey");
		certificate 	= publickeyStore.getKeyStore().getCertificate(keyAlias);
		if(certificate == null) {
			throw new Exception("Key alias " + keyAlias + " not found");
		}
		return certificate;
	}
	private PublicKey getPublicKey(String keyAlias) throws Exception {
		return getCertificate(keyAlias).getPublicKey();
	}

	private PrivateKey getPrivateKey(String keyAlias) throws Exception {
		PrivateKeyStore privatekeyStore;
		PrivateKey privateKey;
		privatekeyStore = getContext().getConnectionProperties().getPrivateKeyStoreProperty("privateKey");
		privateKey 		= (PrivateKey) privatekeyStore.getKeyStore().getKey(keyAlias, privatekeyStore.getPassword().toCharArray());
		if(privateKey == null) {
			throw new Exception("Key alias " + keyAlias + " not found");
		}
		return privateKey;
	}

	@Override
	public BoomiDataSecurityConnection getConnection() {
		return (BoomiDataSecurityConnection) super.getConnection();
	}

	private void log(Logger logger, boolean log, String message) {
		if(log) {
			logger.fine(message);
		}
	}
	
}