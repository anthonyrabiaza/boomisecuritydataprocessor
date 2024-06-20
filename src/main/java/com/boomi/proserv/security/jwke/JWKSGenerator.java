package com.boomi.proserv.security.jwke;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JWKSGenerator {

    public static Map<String, String> generateKey(String use, String alg) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime256v1");
        keyGen.initialize(ecSpec);

        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Map<String, String> keyMap = new HashMap<>();
        keyMap.put("use", use);
        keyMap.put("kty", "EC");
        keyMap.put("alg", alg);
        keyMap.put("crv", "P-256");

        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            keyMap.put("x", Base64.getEncoder().encodeToString(ecPublicKey.getW().getAffineX().toByteArray()));
            keyMap.put("y", Base64.getEncoder().encodeToString(ecPublicKey.getW().getAffineY().toByteArray()));
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        String kid = use + "-" + sdf.format(new Date());
        keyMap.put("kid", kid);

        return keyMap;
    }

    public static String generateJwks() throws Exception {

        Map<String, String> signingKeyMap = generateKey("sig", "ES256");
        Map<String, String> encryptionKeyMap = generateKey("enc", "ECDH-ES+A256KW");

        JSONObject jwks = new JSONObject();
        jwks.append("keys", new JSONObject(signingKeyMap));
        jwks.append("keys", new JSONObject(encryptionKeyMap));

        String jwksJsonString = jwks.toString();

        // Encode the JWKS JSON as Base64
        byte[] jwksBytes = jwksJsonString.getBytes("UTF-8");
        String jwksBase64 = Base64.getEncoder().encodeToString(jwksBytes);

        return jwksBase64;

    }

    public String fetchJWKS(String jwksUrl) throws Exception {
        URL url = new URL(jwksUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new Exception("Failed to fetch JWKS, HTTP response code: " + responseCode);
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        byte[] encodedBytes = Base64.getEncoder().encode(response.toString().getBytes());
        return new String(encodedBytes);
    }
}





