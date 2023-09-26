package com.boomi.proserv.security.pgp;

//import org.bouncycastle.bcpg.ArmoredOutputStream;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
//import org.bouncycastle.openpgp.PGPException;
//import org.bouncycastle.openpgp.PGPPublicKey;
//import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
//import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.security.SecureRandom;

/**
 * Encrypting PGPEncrypting
 * @author ngkx174@gmail.com
 *
 */
public class PGPEncrypting extends PGP {
//    public String encrypt(String message, PGPPublicKey pgpPublicKey, int symmetricAlgorithm, boolean withIntegrityCheck) throws IOException, PGPException {
//        PGPEncryptedDataGenerator encryptor = new PGPEncryptedDataGenerator(
//                new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
//                        .setWithIntegrityPacket(withIntegrityCheck)
//                        .setSecureRandom(new SecureRandom())
//                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//        );
//
//        // Add public key
//        encryptor.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
//
//        // write out the cipher text
//        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
//        OutputStream armoredOutput = encryptedOutput;
//        armoredOutput = new ArmoredOutputStream(armoredOutput);
//
//        // Created an encrypted output stream
//        OutputStream encOut = encryptor.open(armoredOutput, message.length());
//        encOut.write(message.getBytes());
//        encOut.close();
//
//        // Tidy up
//        armoredOutput.close();
//        encryptor.close();
//
//        // Write return values
//        String encryptedString = new String(encryptedOutput.toByteArray());
//        encryptedOutput.close();
//        return encryptedString;
//    }

}
