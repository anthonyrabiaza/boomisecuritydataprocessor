package com.boomi.proserv.security.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

/**
 * Sign and Encrypt - Performs signing, compression and encryption in one method
 * @author ngkx174@gmail.com
 *
 */
public class PGPSignAndEncrypt {
    public String signAndEncrypt(String message, PGPSecretKey pgpSecretKey, PGPPublicKey pgpPublicKey, String privateKeyPassphrase, int hashingAlgorithm, int compressionAlgorithm, int symmetricAlgorithm, String fileName, boolean withIntegrityCheck) throws Exception {
        // Define the security provider
        Security.addProvider(new BouncyCastleProvider());

        // Extract the PGP Private key
        PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKeyPassphrase.toCharArray());
        PGPPrivateKey pgpPrivateKey = pgpSecretKey.extractPrivateKey(keyDecryptor);

        // Setup signature generator
        PGPSignatureGenerator signatureGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(
                        pgpSecretKey.getPublicKey().getAlgorithm(), hashingAlgorithm
                ).setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );

        // Initialize the signature generator for signing
        signatureGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

        // First Compress the message
        ByteArrayOutputStream zippedOutput = new ByteArrayOutputStream();
        PGPCompressedDataGenerator zippedData = new PGPCompressedDataGenerator(compressionAlgorithm);

        // Define an outbound BCPG Output Stream
        BCPGOutputStream outPackets = new BCPGOutputStream(zippedData.open(zippedOutput));

        // Configure the signature generator to encode outbound packets
        signatureGen.generateOnePassVersion(false).encode(outPackets);

        // Define the zipped packets output stream
        OutputStream zippedPacket = new PGPLiteralDataGenerator().open(
                outPackets,
                PGPLiteralData.BINARY, // BINARY | TEXT | UTF8
                fileName,
                message.length(),
                new Date()
        );

        // Write out the zipped data to the zippedBytes byte array
        zippedPacket.write(message.getBytes(StandardCharsets.UTF_8));
        signatureGen.update(message.getBytes(StandardCharsets.UTF_8));

        // Generate the signature
        signatureGen.generate().encode(outPackets);

        // Close out streams
        zippedPacket.close();
        zippedData.close();

        // Setup a Byte Array from the zipped output
        byte[] zippedBytes = zippedOutput.toByteArray();
        zippedOutput.close();

        // Second Encrypt the compressed message
        PGPEncryptedDataGenerator encryptor = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );

        // Add public key
        encryptor.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));

        // write out the cipher text
        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
        OutputStream armoredOutput = encryptedOutput;
        armoredOutput = new ArmoredOutputStream(armoredOutput);

        // Created an encrypted output stream
        OutputStream encOut = encryptor.open(armoredOutput, zippedBytes.length);
        encOut.write(zippedBytes);
        encOut.close();

        // Tidy up
        armoredOutput.close();
        encryptor.close();

        // Write return values
        String encryptedString = new String(encryptedOutput.toByteArray());
        encryptedOutput.close();
        return encryptedString;
    }
}
