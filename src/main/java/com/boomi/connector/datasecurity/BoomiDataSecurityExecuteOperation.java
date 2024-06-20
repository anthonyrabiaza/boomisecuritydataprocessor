package com.boomi.connector.datasecurity;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.boomi.connector.api.*;
import com.boomi.connector.util.BaseUpdateOperation;
import com.boomi.proserv.security.authentication.AuthCodeHandler;
import com.boomi.proserv.security.authentication.AuthCodeHandlerFactory;
import com.boomi.proserv.security.authentication.NimbusJOSEAuthenticationCodeHandler;
import com.boomi.proserv.security.encrypting.JWEEncrypting;
import com.boomi.proserv.security.encrypting.SMIMEEncrypting;
import com.boomi.proserv.security.encrypting.X509Encrypting;
import com.boomi.proserv.security.jwke.JWKSGenerator;
import com.boomi.proserv.security.pkce.CodeGenerator;
import com.boomi.proserv.security.signing.JWSSigning;
import com.boomi.proserv.security.signing.X509Signing;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

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
			case "PKCE_CODE_GENERATOR":
				executeUpdatePKCECodeGenerator(request, response);
				break;
			case "DPOP_GENERATOR":
				executeUpdateDPoPGenerator(request, response);
				break;
			case "CLIENT_ASSERTION_GENERATOR":
				executeUpdateClientAssertionGenerator(request, response);
				break;
			case "JWKS_GENERATOR":
				executeUpdateJWKSGenerator(request, response);
				break;
			case "JWT_VERIFIER":
				executeUpdateJWTVerifier(request, response);
				break;
			case "DECRYPT_DATA":
				executeUpdateDecryptData(request, response);
			case "DECRYPT_SINGPASS_DATA":
				executeUpdateDecryptSingpassData(request, response);
				break;
			case "JWKS_DATA":
				executeUpdateJWKSData(request, response);
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

	protected void executeUpdatePKCECodeGenerator(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdatePKCECodeChallenge received");

		String algorithm 		= getContext().getOperationProperties().getProperty("algorithm");

		log(logger, log, "ARA: algorithm is " + algorithm);

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String codeVerifier = "ERROR";
				String codeChallenge = "ERROR";

				// Generates Code Challenge based on generated Code Verifier
				codeVerifier = CodeGenerator.generateCodeVerifier();
				codeChallenge = CodeGenerator.generateCodeChallenge(codeVerifier, algorithm);

				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(PKCEWrapMessageToXML(codeVerifier,codeChallenge)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdateDPoPGenerator(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateDPoPGenerator received");

		String implementation = getContext().getOperationProperties().getProperty("implementation");

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());

				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(message)));

				Node node_url = findXMLField(document, "url");
				Node node_url_method = findXMLField(document, "url_method");
				Node node_client_id = findXMLField(document, "client_id");
				Node node_access_token_hash = findXMLField(document, "access_token_hash");
				Node node_jwks_json = findXMLField(document, "jwks_json");
				Node node_uuid = findXMLField(document, "uuid");
				Node node_serialized_key_data = findXMLField(document, "serialized_key_data");

				String url = (node_url != null) ? node_url.getTextContent() : null;
				String url_method = (node_url_method != null) ? node_url_method.getTextContent() : null;
				String client_id = (node_client_id != null) ? node_client_id.getTextContent() : null;
				String access_token_hash = (node_access_token_hash != null) ? node_access_token_hash.getTextContent() : null;
				String jwks_json = (node_jwks_json != null) ? node_jwks_json.getTextContent() : null;
				String uuid = (node_uuid != null) ? node_uuid.getTextContent() : null;
				String serialized_key_data = (node_serialized_key_data != null) ? node_serialized_key_data.getTextContent() : null;

				// Use the factory to get the appropriate AuthCodeHandler implementation
				AuthCodeHandler handler = AuthCodeHandlerFactory.getAuthCodeHander(implementation);
				handler.generateAuthentication(url, client_id, url_method, access_token_hash, jwks_json, uuid, serialized_key_data);
				String Dpop                                = handler.getdpop();
				String ClientAssertion                     = handler.getclientAssertion();
				String SerializedKeyData                     = handler.getserializedKeyData();

				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(DPoPWrapMessageToXML(url,client_id,ClientAssertion,Dpop, SerializedKeyData)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdateClientAssertionGenerator(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateDPoPGenerator received");

		String implementation = getContext().getOperationProperties().getProperty("implementation");

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());

				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(message)));

				Node node_url = findXMLField(document, "url");
				Node node_client_id = findXMLField(document, "client_id");
				Node node_jwks_json = findXMLField(document, "jwks_json");
				Node node_auth_code = findXMLField(document, "auth_code");

				String url = (node_url != null) ? node_url.getTextContent() : null;
				String client_id = (node_client_id != null) ? node_client_id.getTextContent() : null;
				String jwks_json = (node_jwks_json != null) ? node_jwks_json.getTextContent() : null;
				String auth_code = (node_auth_code != null) ? node_auth_code.getTextContent() : null;

				NimbusJOSEAuthenticationCodeHandler handler = new NimbusJOSEAuthenticationCodeHandler();
				handler.generateAuthenticationSingpass(url, client_id, jwks_json, auth_code);

				String ClientAssertion                     = handler.getclientAssertion();

				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(ClientAssertionWrapMessageToXML(url,client_id,ClientAssertion)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdateJWTVerifier(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateJWTVerifier received");

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());

				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(message)));

				Node node_jwtToken = findXMLField(document, "jwtToken");
				Node node_jwksString = findXMLField(document, "jwksUrl");


				String jwtToken = (node_jwtToken != null) ? node_jwtToken.getTextContent() : null;
				String jwksString = (node_jwksString != null) ? node_jwksString.getTextContent() : null;
				NimbusJOSEAuthenticationCodeHandler handler = new NimbusJOSEAuthenticationCodeHandler();
				DecodedJWT tokenJWT = handler.verifyToken(jwtToken, jwksString);
				String validationResult;
				if (tokenJWT != null) { // TO DO USE BOOLEAN //
					validationResult = "Pass";
				} else {
					validationResult = "Fail";
				}

				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(JWTVerifierWrapMessageToXML(validationResult)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdateDecryptData(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateDecryptData received");

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());

				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(message)));


				Node node_jwksUrl = findXMLField(document, "jwksUrl");
				Node node_result = findXMLField(document, "result");
				Node node_encKeyInfoJson = findXMLField(document, "encKeyInfoJson");

				String jwksUrl = (node_jwksUrl != null) ? node_jwksUrl.getTextContent() : null;
				String result = (node_result != null) ? node_result.getTextContent() : null;
				String encKeyInfoJson = (node_encKeyInfoJson != null) ? node_encKeyInfoJson.getTextContent() : null;

				NimbusJOSEAuthenticationCodeHandler handler = new NimbusJOSEAuthenticationCodeHandler();
				String PersonsJson = handler.getdecryptedData(result, encKeyInfoJson, jwksUrl);
				String encodedPersonsJson = Base64.getEncoder().encodeToString(PersonsJson.getBytes());
				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(DecryptDataWrapMessageToXML(encodedPersonsJson)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdateDecryptSingpassData(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateDecryptData received");

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());

				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(message)));


				Node node_jwksUrl = findXMLField(document, "jwksUrl");
				Node node_result = findXMLField(document, "result");
				Node node_encKeyInfoJson = findXMLField(document, "encKeyInfoJson");

				String jwksUrl = (node_jwksUrl != null) ? node_jwksUrl.getTextContent() : null;
				String result = (node_result != null) ? node_result.getTextContent() : null;
				String encKeyInfoJson = (node_encKeyInfoJson != null) ? node_encKeyInfoJson.getTextContent() : null;

				NimbusJOSEAuthenticationCodeHandler handler = new NimbusJOSEAuthenticationCodeHandler();
				String PersonsJson = handler.getdecryptedSingpassData(result, encKeyInfoJson, jwksUrl);
				String encodedPersonsJson = Base64.getEncoder().encodeToString(PersonsJson.getBytes());
				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(DecryptSingpassDataWrapMessageToXML(encodedPersonsJson)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}

	protected void executeUpdateJWKSData(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateDecryptData received");

		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");

				String message = BoomiDataSecurityConnector.inputStreamToString(input.getData());

				DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
				DocumentBuilder builder = factory.newDocumentBuilder();
				Document document = builder.parse(new InputSource(new StringReader(message)));


				Node node_jwksUrl = findXMLField(document, "jwksUrl");

				String jwksUrl = (node_jwksUrl != null) ? node_jwksUrl.getTextContent() : null;

				JWKSGenerator jwksGenerator = new JWKSGenerator();
				String jwksResponse = jwksGenerator.fetchJWKS(jwksUrl);
				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(JWKSDataWrapMessageToXML(jwksResponse)));

				log(logger, log, "ARA: Document processed");
			} catch (Exception e) {
				logger.log(Level.SEVERE, "Details of Exception:", e);
				ResponseUtil.addExceptionFailure(response, input, e);
			}
		}
	}



	protected void executeUpdateJWKSGenerator(UpdateRequest request, OperationResponse response) {
		Logger logger = response.getLogger();
		boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

		log(logger, log, "ARA: executeUpdateJWKSGenerator received");


		for (ObjectData input : request) {
			try {

				log(logger, log, "ARA: Processing document ...");


				// Generate JWKS Keys
				JWKSGenerator jwksGenerator = new JWKSGenerator();
				String jwks = jwksGenerator.generateJwks();

				response.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(JWKSWrapMessageToXML(String.valueOf(jwks))));

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

	private String PKCEWrapMessageToXML(String codeVerifier, String codeChallenge){
		return "<Execute_PKCE_Code_Generator_Response>" +
				"<code_verifier>" + codeVerifier + "</code_verifier>" +
				"<code_challenge>" + codeChallenge + "</code_challenge>" +
				"</Execute_PKCE_Code_Generator_Response>";
	}

	private String DPoPWrapMessageToXML(String url, String client_id, String client_assertion, String dpop, String serialized_key_data){
		return "<Execute_DPoP_Generator_Response>" +
				"<url>" + url + "</url>" +
				"<client_id>" + client_id + "</client_id>" +
				"<client_assertion>" + client_assertion + "</client_assertion>" +
				"<dpop>" + dpop + "</dpop>" +
				"<serialized_key_data>" + serialized_key_data + "</serialized_key_data>" +
				"</Execute_DPoP_Generator_Response>";
	}

	private String ClientAssertionWrapMessageToXML(String url, String client_id, String client_assertion){
		return "<Execute_ClientAssertion_Generator_Response>" +
				"<url>" + url + "</url>" +
				"<client_id>" + client_id + "</client_id>" +
				"<client_assertion>" + client_assertion + "</client_assertion>" +
				"</Execute_ClientAssertion_Generator_Response>";
	}

	private String JWTVerifierWrapMessageToXML(String isValidString){
		return "<Execute_JWT_Verifier_Response>" +
				"<result>" + isValidString + "</result>" +
				"</Execute_JWT_Verifier_Response>";
	}

	private String DecryptDataWrapMessageToXML(String jsonData){
		return "<Execute_Decrypt_Data_Response>" +
				"<personsjson>" + jsonData + "</personsjson>" +
				"</Execute_Decrypt_Data_Response>";
	}

	private String DecryptSingpassDataWrapMessageToXML(String jsonData){
		return "<Execute_Decrypt_Singpass_Data_Response>" +
				"<nricjson>" + jsonData + "</nricjson>" +
				"</Execute_Decrypt_Singpass_Data_Response>";
	}

	private String JWKSDataWrapMessageToXML(String jwksString){
		return "<Execute_JWKS_Data_Response>" +
				"<jwksString>" + jwksString + "</jwksString>" +
				"</Execute_JWKS_Data_Response>";
	}

	private String JWKSWrapMessageToXML(String jwks){
		return "<Execute_JWKS_Generator_Response>" +
				"<jwks_keys>" + jwks + "</jwks_keys>" +
				"</Execute_JWKS_Generator_Response>";
	}

	private static Node findXMLField(Document document, String fieldName) {
		Node root = document.getDocumentElement();
		NodeList childNodes = root.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node childNode = childNodes.item(i);
			if (childNode.getNodeType() == Node.ELEMENT_NODE && childNode.getNodeName().equals(fieldName)) {
				return childNode;
			}
		}
		return null;
	}

	private void log(Logger logger, boolean log, String message) {
		if(log) {
			logger.fine(message);
		}
	}
	
}