package com.boomi.proserv.security.pgp;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.openpgp.PGPCompressedData;
//import org.bouncycastle.openpgp.PGPEncryptedDataList;
//import org.bouncycastle.openpgp.PGPException;
//import org.bouncycastle.openpgp.PGPObjectFactory;
//import org.bouncycastle.openpgp.PGPPrivateKey;
//import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
//import org.bouncycastle.openpgp.PGPSecretKey;
//import org.bouncycastle.openpgp.PGPUtil;
//import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
//import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
//import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
//import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class PGPDecrypt extends PGP {
//    public String decrypt(PGPSecretKey secretKey, String encryptedMessage, String privateKeyPassphrase) throws IOException, PGPException {
//        // Add the security provider
//        Security.addProvider(new BouncyCastleProvider());
//
//        // Extract the private key
//        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKeyPassphrase.toCharArray()));
//
//        // Initialize the PGP object factory
//        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedMessage.getBytes())), new JcaKeyFingerprintCalculator());
//
//        // Get the encrypted data object
//        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
//        PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.getEncryptedDataObjects().next();
//
//        // Decrypt the data
//        InputStream decryptedInputStream = publicKeyEncryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
//
//        // Initialize the PGP object factory with the decrypted data
//        pgpObjectFactory = new PGPObjectFactory(decryptedInputStream, new JcaKeyFingerprintCalculator());
//
//        // Get the compressed data object
//        PGPCompressedData compressedData = (PGPCompressedData) pgpObjectFactory.nextObject();
//        InputStream decompressedInputStream = new BufferedInputStream(compressedData.getDataStream());
//
//        // Convert decrypted data to byte array
//        ByteArrayOutputStream decompressedBytes = new ByteArrayOutputStream();
//        Streams.pipeAll(decompressedInputStream, decompressedBytes);
//
//        byte[] decompressedData = decompressedBytes.toByteArray();
//
//        // clean up
//        decompressedInputStream.close();
//        decryptedInputStream.close();
//
//        return new String(decompressedData, StandardCharsets.UTF_8);
//
//    }

}
