package com.boomi.proserv.security.authentication;

import com.auth0.jwt.interfaces.DecodedJWT;
import java.security.interfaces.ECPrivateKey;
public interface AuthCodeHandler {

    void generateAuthentication(String url, String clientId, String method, String ath, String keyInfoJson, String uuid, String KeyData) throws Exception;

    void generateAuthenticationSingpass(String url, String clientId, String keyInfoJson, String authCode) throws Exception;
    DecodedJWT verifyToken (String token, String jwksString) throws Exception;

    String getdecryptedData (String result, String encKeyInfoJson, String jwksString) throws Exception;

    String getPayload (String result, ECPrivateKey privateKey) throws Exception;

    String getdpop();

    String getclientAssertion();

    String getserializedKeyData();
}
