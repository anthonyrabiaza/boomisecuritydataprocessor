package com.boomi.proserv.security.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class JOSE4JAuthenticationCodeHandler implements AuthCodeHandler{

    private   String ES256_ALGORITHM = "ES256";
    private   String JWT_TYPE = "JWT";
    private   String DPOP_JWT_TYPE = "dpop+jwt";

  //  @Override
    private Map<String, Object> generateEphemeralKeysWithKid() throws Exception {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1"); // P-256 curve

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ecGenSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate a random UUID as "kid" (Key ID)
        String kid = RandomStringUtils.randomAlphanumeric(40);

        Map<String, Object> result = new HashMap<>();
        result.put("keyPair", keyPair);
        result.put("kid", kid);

        return result;
    }

    private String generateDpop(String url, String ath, String method, KeyPair ephemeralKeyPair, String keyId) throws Exception {
        Date now = new Date();
        long iat = now.getTime() / 1000;
        long exp = iat + 120;
        String jti = RandomStringUtils.randomAlphanumeric(40);

        JwtClaims claims = new JwtClaims();
        claims.setClaim("htu", url);
        claims.setClaim("htm", method);
        claims.setClaim("jti", jti);
        claims.setIssuedAt(NumericDate.fromSeconds(iat));
        claims.setExpirationTime(NumericDate.fromSeconds(exp));

        if (ath != null && !ath.isEmpty()) {
            claims.setClaim("ath", ath);
        }

        // Create a JSON Web Signature
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(ES256_ALGORITHM);

        ECPublicKey publicKey = (ECPublicKey) ephemeralKeyPair.getPublic();
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineX().toByteArray());
        String y = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getW().getAffineY().toByteArray());
        String kid = keyId;

        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("kid", kid);
        jwk.put("crv", "P-256");
        jwk.put("x", x);
        jwk.put("y", y);
        jwk.put("use", "sig");
        jwk.put("alg", ES256_ALGORITHM);

        jws.setHeader("typ", DPOP_JWT_TYPE);
        jws.setHeader("jwk", jwk);
        jws.setKey(ephemeralKeyPair.getPrivate());
        jws.sign();
        return jws.getCompactSerialization();
    }

    private String generateClientAssertion(String url, String clientId, PrivateKey privateSigningKey, String jwkThumbprint, String keyId) throws Exception {
        Date now = new Date();
        long iat = now.getTime() / 1000;
        long exp = iat + 300;

        JwtClaims claims = new JwtClaims();
        claims.setClaim("sub", clientId);
        claims.setClaim("jti", RandomStringUtils.randomAlphanumeric(40));
        claims.setClaim("aud", url);
        claims.setClaim("iss", clientId);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(exp));

        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jkt", jwkThumbprint);

        claims.setClaim("cnf", cnf);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        System.out.println(claims.toJson());
        jws.setAlgorithmHeaderValue(ES256_ALGORITHM);
        jws.setKey(privateSigningKey);
        jws.setHeader("typ", JWT_TYPE);
        jws.setHeader("kid", keyId);

        return jws.getCompactSerialization();
    }

    private String dpop;
    private String clientAssertion;
    private String serializedKeyData;
    private KeyPair ephemeralKeyPair;

    public void generateAuthentication (String url, String clientId, String method, String ath, String keyInfoJson, String uuid, String KeyData) throws Exception {

        if (ath != null && !ath.isEmpty()) {
            Map<String, Object> keyPairWithKid = deserializeKeysFromString(KeyData);
            KeyPair ephemeralKeyPair = (KeyPair) keyPairWithKid.get("keyPair");
            String kid = (String) keyPairWithKid.get("kid");
            String dpop               = generateDpop(url, ath, method, ephemeralKeyPair, kid);
            this.dpop = dpop;
        } else {

            Map<String, Object> keyPairWithKid = generateEphemeralKeysWithKid();
            KeyPair ephemeralKeyPair = (KeyPair) keyPairWithKid.get("keyPair");
            String kid = (String) keyPairWithKid.get("kid");
            String dpop                = generateDpop(url, ath, method, ephemeralKeyPair, kid);

            // Decode the Base64-encoded JSON string
            byte[] decodedBytes             = Base64.getDecoder().decode(keyInfoJson);
            String decodedJson              = new String(decodedBytes, StandardCharsets.UTF_8);
            JSONObject jwksObject           = new JSONObject(decodedJson);
            JSONArray keysArray             = jwksObject.getJSONArray("keys");
            JSONObject keyObject            = keysArray.getJSONObject(0);
            Map<String, Object> keyPair = extractJWKS(keyObject);

            PublicKey publicKey             = (PublicKey) keyPair.get("publicKey");
            PrivateKey privateKey           = (PrivateKey) keyPair.get("privateKey");
            String JWKSkid                  = (String) keyPair.get("kid");
            JsonWebKey jwk = JsonWebKey.Factory.newJwk(ephemeralKeyPair.getPublic());
            String jwkThumbprint            = jwk.calculateBase64urlEncodedThumbprint("SHA-256");
            String clientAssertion          = generateClientAssertion(url, clientId, privateKey, jwkThumbprint, JWKSkid);
            String serializedKeyData = serializeKeysToString(keyPairWithKid);
            this.dpop = dpop;
            this.clientAssertion = clientAssertion;
            this.serializedKeyData = serializedKeyData;
            this.ephemeralKeyPair = ephemeralKeyPair;
        }
    }
    public String getdpop() { return dpop;}
    public String getclientAssertion() {
        return clientAssertion;
    }
    public String getserializedKeyData() {
        return serializedKeyData;
    }
    public KeyPair getephemeralKeyPair() {
        return ephemeralKeyPair;
    }

    public void generateAuthenticationSingpass (String url, String clientId, String keyInfoJson, String authCode) throws Exception {


        // Decode the Base64-encoded JSON string
        byte[] decodedBytes             = Base64.getDecoder().decode(keyInfoJson);
        String decodedJson              = new String(decodedBytes, StandardCharsets.UTF_8);
        JSONObject jwksObject           = new JSONObject(decodedJson);
        JSONArray keysArray             = jwksObject.getJSONArray("keys");
        JSONObject keyObject            = keysArray.getJSONObject(0);
        Map<String, Object> keyPair = extractJWKS(keyObject);

        PublicKey publicKey             = (PublicKey) keyPair.get("publicKey");
        PrivateKey privateKey           = (PrivateKey) keyPair.get("privateKey");
        String JWKSkid                  = (String) keyPair.get("kid");
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(ephemeralKeyPair.getPublic());
        String jwkThumbprint            = jwk.calculateBase64urlEncodedThumbprint("SHA-256");
        String clientAssertion          = generateClientAssertion(url, clientId, privateKey, jwkThumbprint, JWKSkid);

        this.clientAssertion = clientAssertion;

    }

    private Map<String, Object> extractJWKS(JSONObject keyObject) throws Exception {
        String dValue = keyObject.getString("d");
        String xValue = keyObject.getString("x");
        String yValue = keyObject.getString("y");
        String kidValue = keyObject.getString("kid");

        byte[] dBytes = Base64.getUrlDecoder().decode(dValue);
        byte[] xBytes = Base64.getUrlDecoder().decode(xValue);
        byte[] yBytes = Base64.getUrlDecoder().decode(yValue);

        ECNamedCurveParameterSpec curveParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
        ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("P-256", curveParameterSpec.getCurve(), curveParameterSpec.getG(), curveParameterSpec.getN());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(1, dBytes), curveSpec);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes)), curveSpec);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Map<String, Object> keyMap = new HashMap<>();
        keyMap.put("publicKey", publicKey);
        keyMap.put("privateKey", privateKey);
        keyMap.put("kid", kidValue);

        return keyMap;
    }

    public DecodedJWT verifyToken(String jwtToken, String jwksString) throws Exception {

        JSONObject jwks = new JSONObject(jwksString);
        JSONArray keys = jwks.getJSONArray("keys");
        JSONObject es256Key = null;
        for (int i = 0; i < keys.length(); i++) {
            JSONObject key = keys.getJSONObject(i);
            if ("ES256".equals(key.optString("alg"))) {
                es256Key = key;
                break;
            }
        }
        if (es256Key == null) {
            throw new Exception("ES256 key not found in JWKS");
        }

        String xValue = es256Key.getString("x");
        String yValue = es256Key.getString("y");
        PublicKey publicKey = getECPublicKey(xValue, yValue);

        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(jwtToken.getBytes());
            byte[] jwtSignature = Base64.getUrlDecoder().decode(jwtToken.split("\\.")[2]);

            if (signature.verify(jwtSignature)) {
                // Verification successful, return the decoded JWT
                return JWT.decode(jwtToken);
            } else {
                throw new Exception("JWT validation fail.");
            }
        } catch (JWTDecodeException | IllegalArgumentException e) {
            throw new Exception("Error decoding or verifying JWT: " + e.getMessage());
        }
    }

    private PublicKey getECPublicKey(String xValue, String yValue) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPoint ecPoint = new ECPoint(new java.math.BigInteger(xValue, 16), new java.math.BigInteger(yValue, 16));
        ECParameterSpec ecParameterSpec = getECParameterSpec();
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
        return keyFactory.generatePublic(ecPublicKeySpec);
    }
    private ECParameterSpec getECParameterSpec() {
        // Define the parameters for the curve secp256r1
        java.math.BigInteger p = new java.math.BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        java.math.BigInteger a = new java.math.BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        java.math.BigInteger b = new java.math.BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        java.math.BigInteger n = new java.math.BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        java.math.BigInteger gx = new java.math.BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
        java.math.BigInteger gy = new java.math.BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
        int h = 1;

        EllipticCurve curve = new EllipticCurve(new ECFieldFp(p), a, b);
        ECPoint basePoint = new ECPoint(gx, gy);
        ECParameterSpec ecParameterSpec = new ECParameterSpec(curve, basePoint, n, h);
        return ecParameterSpec;
    }

    public String getdecryptedData(String result, String encKeyInfoJson, String jwksString) throws Exception {

        byte[] decodedBytes = Base64.getDecoder().decode(encKeyInfoJson);
        String decodedJson = new String(decodedBytes, StandardCharsets.UTF_8);
        try {
            // Parse the JWKS as a JSON string
            JsonWebKeySet jwks = new JsonWebKeySet(decodedJson);

            // Extract the first key from the JWKS
            JsonWebKey jwk = jwks.getJsonWebKeys().get(0);

            // Get the private key
            ECPrivateKey privateKey = (ECPrivateKey) ((EllipticCurveJsonWebKey) jwk).getPrivateKey();
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
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setKey(privateKey);
        jwe.setCompactSerialization(result);
        String decryptedMessage = jwe.getPayload();
        return decryptedMessage;
    }

    private String serializeKeysToString(Map<String, Object> keyPairWithKid) {
        try {
            // Serialize the KeyPair
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(keyPairWithKid);
            }
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, Object> deserializeKeysFromString(String serializedKeyPair) {
        try {
            // Convert the Base64 string back to bytes
            byte[] keyPairBytes = Base64.getDecoder().decode(serializedKeyPair);

            // Deserialize the KeyPair
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(keyPairBytes))) {
                return (Map<String, Object>) ois.readObject();
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}