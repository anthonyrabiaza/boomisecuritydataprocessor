package com.boomi.connector.datasecurity;

import com.boomi.connector.api.*;
import com.boomi.connector.util.BaseGetOperation;
import com.boomi.proserv.security.encrypting.X509Encrypting;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.logging.Logger;

public class BoomiDataSecurityGetOperation extends BaseGetOperation {

    protected BoomiDataSecurityGetOperation(BoomiDataSecurityConnection connection) {
        super(connection);
    }

    @Override
    protected void executeGet(GetRequest getRequest, OperationResponse operationResponse) {
        Logger logger = operationResponse.getLogger();
        boolean log = getContext().getConnectionProperties().getBooleanProperty("logging");

        log(logger, log, "ARA: executeGet received");

        String action 						= getContext().getOperationProperties().getProperty("action");
        String standard 					= getContext().getOperationProperties().getProperty("standard");
        String encryptingAlgorithm			= getContext().getOperationProperties().getProperty("encryptingAlgorithm");
        String keyAlias						= getContext().getOperationProperties().getProperty("keyAlias");
        Boolean alwaysUsePrivateKey			= getContext().getOperationProperties().getBooleanProperty("alwaysUsePrivateKey");
        int salt			                = getContext().getOperationProperties().getLongProperty("salt").intValue();

        ObjectIdData input = getRequest.getObjectId();
        String message = input.getObjectId();

        PrivateKey privateKey;
        PublicKey publicKey;
        String result = "ERROR";

        if(message!=null) {
            try {
                switch (action) {
                    case "encrypt":
                        switch (standard) {
                            case "x509":
                                if(alwaysUsePrivateKey) {
                                    publicKey = getPublicKeyFromPrivateKeyStore(keyAlias);
                                } else {
                                    publicKey = getPublicKey(keyAlias);
                                }
                                result = new X509Encrypting().encrypt(message, salt, publicKey, encryptingAlgorithm);
                                break;
                        }
                        break;
                    case "decrypt":
                        switch (standard) {
                            case "x509":
                                privateKey = getPrivateKey(keyAlias);
                                result = new X509Encrypting().decrypt(message, salt, privateKey, encryptingAlgorithm);
                                break;
                        }
                        break;
                }
                operationResponse.addResult(input, OperationStatus.SUCCESS, "200", "OK", ResponseUtil.toPayload(wrapMessageToXML(action,result)));
            } catch (Exception e) {
                ResponseUtil.addExceptionFailure(operationResponse, input, e);
            }
        }
    }

    private PublicKey getPublicKey(String keyAlias) throws Exception {
        PublicKeyStore publickeyStore;
        PublicKey publicKey;
        Certificate certificate;
        publickeyStore 	= getContext().getConnectionProperties().getPublicKeyStoreProperty("publicKey");
        certificate 	= publickeyStore.getKeyStore().getCertificate(keyAlias);
        if(certificate == null) {
            throw new Exception("Key alias " + keyAlias + " not found");
        }
        publicKey 		= certificate.getPublicKey();
        return publicKey;
    }

    private PublicKey getPublicKeyFromPrivateKeyStore(String keyAlias) throws Exception {

        PrivateKeyStore privatekeyStore;
        Certificate certificate;
        PublicKey publicKey;
        privatekeyStore = getContext().getConnectionProperties().getPrivateKeyStoreProperty("privateKey");
        certificate     = privatekeyStore.getKeyStore().getCertificate(keyAlias);
        if(certificate == null) {
            throw new Exception("Key alias " + keyAlias + " not found");
        }
        publicKey 		= certificate.getPublicKey();
        return publicKey;
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

    private String wrapMessageToXML(String action, String message){
        switch(action) {
            case "encrypt":
                return "<Get_Encrypt><encryptedValue>" + message + "</encryptedValue></Get_Encrypt>";
            case "decrypt":
                return "<Get_Decrypt><decryptedValue>" + message + "</decryptedValue></Get_Decrypt>";
        }
        return null;
    }

    private void log(Logger logger, boolean log, String message) {
        if(log) {
            logger.fine(message);
        }
    }
}
