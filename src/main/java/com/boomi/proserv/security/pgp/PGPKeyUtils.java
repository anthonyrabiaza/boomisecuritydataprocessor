package com.boomi.proserv.security.pgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.IOException;
import java.io.InputStream;

/**
 * Utility for PGP functions
 * @author ngkx174@gmail.com
 *
 */
public class PGPKeyUtils {
    public static PGPSecretKey getPGPPrivateKey(InputStream privateKeyStream) throws IOException, PGPException {

        // Create an OpenPGP Ring Collection with the privateKeyStream decoded input stream
        PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyStream), new JcaKeyFingerprintCalculator());

        // Iterate over the Key Ring Collection
        for (PGPSecretKeyRing keyRing : keyRingCollection) {
            for (PGPSecretKey key : keyRing) {
                // Return the first Signing Key we find in the Key Ring Collection
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        // Throw an exception if we cannot extract a private key from the supplied certificate
        throw new PGPException("unable to extract a private key from the given private key string.");
    }

    public static PGPPublicKey getPGPPublicKey(InputStream publicCertStream) throws IOException, PGPException {

        // Create an OpenPGP Ring Collection with the publicCertStream decoded input stream
        PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicCertStream), new JcaKeyFingerprintCalculator());

        // Iterate over the Key Ring Collection
        for (PGPPublicKeyRing keyRing : keyRingCollection) {
            for (PGPPublicKey key : keyRing) {
                // Return the first Encryption Key we find in the Key Ring Collection
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        // Throw an exception if we cannot extract a public key from the supplied certificate
        throw new PGPException("unable to extract a public key from the given public key string.");
    }

}