package com.boomi.proserv.security.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class NimbusJOSEAuthenticationCodeHandler implements AuthCodeHandler {
    private ECKey generateEphemeralKeys() throws Exception {
        try {

            String kid = RandomStringUtils.randomAlphanumeric(40);

            ECKey jwk = new ECKeyGenerator(Curve.P_256)
                    .keyID(kid)
                    .generate();

            return jwk;
        } catch(Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    private String generateDpop(String url, String method, ECKey sessionPopKeyPair, AccessToken ath, String uuid) throws Exception {

        SignedJWT proof = null;
        try {
            Date iat = new Date();
            JWTID jti = new JWTID(40);
            URI uri = new URI(url);
            // 2 minutes in milliseconds
            long twoMinutesInMillis = 2 * 60 * 1000;
            Date exp = new Date(iat.getTime() + twoMinutesInMillis);

            JWK jwk = sessionPopKeyPair;

            JOSEObjectType TYPE = new JOSEObjectType("dpop+jwt");

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(TYPE)
                    .jwk(jwk.toPublicJWK())
                    .build();

            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .jwtID(jti.getValue())
                    .claim("htm", method)
                    .issueTime(iat)
                    .expirationTime(exp);

            if (ath != null) {
                uri = new URI(url+"/"+uuid);
                builder = builder.claim("ath", computeSHA256(ath).toString())
                        .claim("htu", uri.toString());
            } else {
                builder = builder.claim("htu", uri.toString());
            }

            JWTClaimsSet jwtClaimsSet = builder.build();

            DefaultJWSSignerFactory factory = new DefaultJWSSignerFactory();
            JWSSigner jwsSigner = factory.createJWSSigner(jwk, JWSAlgorithm.ES256);


            proof = new SignedJWT(jwsHeader, jwtClaimsSet);
            proof.sign(jwsSigner);

        } catch(Exception e) {
            throw new Exception(e.getMessage());
        }
        return proof.serialize();
    }

    private String generateClientAssertion(final String url, final String clientId, Base64URL jktThumbprint, String keyId, ECPrivateKey privateSigningKey)
            throws Exception {

        Map<String, Object> cnf = new HashMap<String, Object>();
        cnf.put("jkt", jktThumbprint.toString());

        String jwt="";
        try {

            final JWSSigner signer = new ECDSASigner(privateSigningKey, Curve.P_256);
            final SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(keyId)
                            .type(JOSEObjectType.JWT).build(),
                    new JWTClaimsSet.Builder()
                            .issuer(clientId)
                            .subject(clientId)
                            .audience(url)
                            .issueTime(new Date())
                            .expirationTime(new Date(System.currentTimeMillis() + 300000L))
                            .jwtID(new JWTID().getValue())
                            .claim("cnf", cnf).build());

            signedJWT.sign(signer);

            jwt = signedJWT.serialize();

        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e.getMessage());
        }
        return jwt;
    }

    private String generateClientAssertionSingpass(final String url, final String clientId, String keyId, ECPrivateKey privateSigningKey, String authCode)
            throws Exception {

        String jwt="";
        try {

            final JWSSigner signer = new ECDSASigner(privateSigningKey, Curve.P_256);
            final SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(keyId)
                            .type(JOSEObjectType.JWT).build(),
                    new JWTClaimsSet.Builder()
                            .issuer(clientId)
                            .subject(clientId)
                            .audience(url)
                            .issueTime(new Date())
                            .expirationTime(new Date(System.currentTimeMillis() + 120000L))
                            .claim("code", authCode).build());

                    signedJWT.sign(signer);

            jwt = signedJWT.serialize();

        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception(e.getMessage());
        }
        return jwt;
    }

    private Base64URL computeSHA256(final AccessToken accessToken)
            throws Exception {
        byte[] hash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            hash = md.digest(accessToken.getValue().getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new Exception(e.getMessage(), e);
        }
        return Base64URL.encode(hash);
    }

    private String dpop;
    private String clientAssertion;
    private String serializedKeyData;

    public void generateAuthentication(String url, String clientId, String method, String ath, String keyInfoJson, String uuid, String KeyData) throws Exception {

        if (ath != null ) {
            ECKey ephemeralKeys = deserializeKeysFromString(KeyData);
            AccessToken bearer = new DPoPAccessToken(ath);
            String dpop = generateDpop(url, method, ephemeralKeys, bearer, uuid);
            this.dpop = dpop;

        } else {
            ECKey ephemeralKeys = generateEphemeralKeys();
            AccessToken bearer = null;
            String dpop = generateDpop(url, method, ephemeralKeys, bearer, uuid);

            // Decode the Base64-encoded JSON string
            byte[] decodedBytes = Base64.getDecoder().decode(keyInfoJson);
            String decodedJson = new String(decodedBytes, StandardCharsets.UTF_8);
            // Parse the JWKS as a JSON string
            JWKSet jwkSet = JWKSet.parse(decodedJson);

            // Extract the first key from the JWKS
            ECKey ecKey = (ECKey) jwkSet.getKeys().get(0);

            // Get the private key
            ECPrivateKey privateKey = ecKey.toECPrivateKey();
            String keyId = ecKey.getKeyID();
            Base64URL jktThumbprint = ephemeralKeys.toPublicJWK().computeThumbprint("SHA-256");
            String clientAssertion = generateClientAssertion(url, clientId, jktThumbprint, keyId, privateKey);

            String serializedKeyData = serializeKeysToString(ephemeralKeys);

            this.dpop = dpop;
            this.clientAssertion = clientAssertion;
            this.serializedKeyData = serializedKeyData;

        }
    }

    public String getdpop() {
        return dpop;
    }
    public String getclientAssertion() {
        return clientAssertion;
    }
    public String getserializedKeyData() {
        return serializedKeyData;
    }


    public void generateAuthenticationSingpass(String url, String clientId, String keyInfoJson, String authCode) throws Exception {


        // Decode the Base64-encoded JSON string
        byte[] decodedBytes = Base64.getDecoder().decode(keyInfoJson);
        String decodedJson = new String(decodedBytes, StandardCharsets.UTF_8);
        // Parse the JWKS as a JSON string
        JWKSet jwkSet = JWKSet.parse(decodedJson);

        // Extract the first key from the JWKS
        ECKey ecKey = (ECKey) jwkSet.getKeys().get(0);

        // Get the private key
        ECPrivateKey privateKey = ecKey.toECPrivateKey();
        String keyId = ecKey.getKeyID();

        String clientAssertionSingpass = generateClientAssertionSingpass(url, clientId, keyId, privateKey, authCode);

        this.clientAssertion = clientAssertionSingpass;

    }

    public DecodedJWT verifyToken(String token, String jwksString) throws Exception {
        JWSObject jwsObj = null;
        DecodedJWT jwt = null;

        try {
            jwsObj = JWSObject.parse(token);

            // Parse the JWKS string

            JWKSet jwkSet = JWKSet.parse(new String(Base64.getDecoder().decode(jwksString)));

            // Get the JWK with the ECC public key

            JWK selectedJWK = jwkSet.getKeyByKeyId(jwsObj.getHeader().getKeyID());

            if (selectedJWK == null) {
                throw new Exception("No matching JWK found.");
            }

            // Create a JWS verifier from the selected JWK
            JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jwsObj.getHeader(),
                    selectedJWK.toECKey().toECPublicKey());

            // Verify the JWT signature
            Boolean flag = jwsObj.verify(verifier);

            if (!flag) {
                throw new Exception("JWT validation fail.");
            } else {
                jwt = JWT.decode(token);
            }
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }

        return jwt;
    }

    public String getdecryptedData(String result, String encKeyInfoJson, String jwksString) throws Exception {

        byte[] decodedBytes = Base64.getDecoder().decode(encKeyInfoJson);
        String decodedJson = new String(decodedBytes, StandardCharsets.UTF_8);
        try {
            // Parse the JWKS as a JSON string
            JWKSet jwkSet = JWKSet.parse(decodedJson);

            // Extract the first key from the JWKS
            ECKey ecKey = (ECKey) jwkSet.getKeys().get(0);

            // Get the private key
            ECPrivateKey privateKey = ecKey.toECPrivateKey();

            String payload = getPayload(result, privateKey);
            DecodedJWT personJWT = verifyToken(payload, jwksString);
            // Convert byte[] to String
            byte[] base64Decode = Base64.getDecoder().decode(personJWT.getPayload());
            String jsonResponse = new String(base64Decode);
            return jsonResponse;

        } catch (ParseException parseException) {
            System.err.println("Failed to parse JWKS: " + parseException.getMessage());
            throw parseException;
        }
    }

    public String getdecryptedSingpassData(String result, String encKeyInfoJson, String jwksString) throws Exception {

        byte[] decodedBytes = Base64.getDecoder().decode(encKeyInfoJson);
        String decodedJson = new String(decodedBytes, StandardCharsets.UTF_8);
        try {
            // Parse the JWKS as a JSON string
            JWKSet jwkSet = JWKSet.parse(decodedJson);

            // Extract the first key from the JWKS
            ECKey ecKey = (ECKey) jwkSet.getKeys().get(0);

            // Get the private key
            ECPrivateKey privateKey = ecKey.toECPrivateKey();

            String payload = getPayload(result, privateKey);
            DecodedJWT personJWT = verifyToken(payload, jwksString);
            // Convert byte[] to String
            byte[] base64Decode = Base64.getDecoder().decode(personJWT.getPayload());
            String jsonResponse = new String(base64Decode);
            return jsonResponse;

        } catch (ParseException parseException) {
            System.err.println("Failed to parse JWKS: " + parseException.getMessage());
            throw parseException;
        }
    }

    public String getPayload(String result, ECPrivateKey privateKey) throws Exception {

        JWEObject jweObject;
        try {
            // Parse JWE & validate headers
            jweObject = EncryptedJWT.parse(result);

            // Set PrivateKey and Decrypt
            JWEDecrypter decrypter = new ECDHDecrypter(privateKey);
            jweObject.decrypt(decrypter);

        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
        // Get String Payload
        String payload = jweObject.getPayload().toString();

        return payload;
    }

    private String serializeKeysToString(ECKey ephemeralKeys) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(ephemeralKeys);
            byte[] keyData = baos.toByteArray();
            return Base64.getEncoder().encodeToString(keyData);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private ECKey deserializeKeysFromString(String base64EncodedKeyData) {
        byte[] keyData = Base64.getDecoder().decode(base64EncodedKeyData);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(keyData);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (ECKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}
