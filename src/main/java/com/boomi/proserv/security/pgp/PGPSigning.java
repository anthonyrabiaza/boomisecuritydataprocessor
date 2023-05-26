package com.boomi.proserv.security.pgp;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Date;

// For Private Key extraction:
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * Signing PGPSigning
 * @author ngkx174@gmail.com
 *
 */
public class PGPSigning extends PGP {
    public String sign(String message, PGPSecretKey pgpSecretKey, String privateKeyPassphrase, int hashingAlgorithm, int compressionAlgorithm) throws Exception {
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
        BCPGOutputStream bcOut = new BCPGOutputStream(zippedData.open(zippedOutput));

        // Define the packets output stream
        OutputStream output = new PGPLiteralDataGenerator().open(
                bcOut,
                PGPLiteralData.BINARY, // BINARY | TEXT | UTF8
                filename,
                message.length(),
                new Date()
        );

        // Write out the data to the byte array
        output.write(message.getBytes(StandardCharsets.UTF_8));
        signatureGen.update(message.getBytes(StandardCharsets.UTF_8));

        // Generate the signature
        signatureGen.generate().encode(bcOut);

        // Close out streams
        output.close();
        bcOut.close();

        // return the zipped output as string
        String signedString = new String(zippedOutput.toByteArray());
        zippedOutput.close();
        return signedString;
    }
}
