package com.boomi.proserv.security.pgp;

import com.boomi.proserv.security.KeyUtils;
import com.boomi.proserv.security.TestSecurityHelper;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class PGPTest {

//    @Test
//    void test() throws Exception {
//        String message 		        = "This is the message to sign";
//        int hashingAlgorithm        = PGPUtil.SHA256;
//        int compressionAlgorithm    = CompressionAlgorithmTags.ZIP;
//        int symmetricKeyAlgorithm   = SymmetricKeyAlgorithmTags.AES_256;
//        boolean withIntegrityCheck  = true;
//        String fileName             = "";
//        String myKeyPassphrase      = "boomi123";
//        String otherKeyPassphrase   = "companyxyz123";
//        String signature            = new PGPSigning().sign(message, TestSecurityHelper.getMyPGPPrivateKey(), myKeyPassphrase, hashingAlgorithm, compressionAlgorithm);
//        System.out.println("Generated signature: " + KeyUtils.encodeToBase64(signature.getBytes()));
//        String encryptedSignature   = new PGPEncrypting().encrypt(message, TestSecurityHelper.getEntityPGPPublicKey(), symmetricKeyAlgorithm, withIntegrityCheck);
//        System.out.println("Encrypted signature: " + encryptedSignature);
//        String encryptAndSignSig    = new PGPSignAndEncrypt().signAndEncrypt(message, TestSecurityHelper.getMyPGPPrivateKey(), TestSecurityHelper.getEntityPGPPublicKey(), myKeyPassphrase, hashingAlgorithm, compressionAlgorithm, symmetricKeyAlgorithm, withIntegrityCheck);
//        System.out.println("Encrypt and sign signature: " + encryptAndSignSig);
//        String decryptedMessage     = new PGPDecrypt().decrypt(TestSecurityHelper.getEntityPGPPrivateKey(), encryptAndSignSig, otherKeyPassphrase);
//        System.out.println(decryptedMessage);
//        // verify part not working
//        //System.out.println("Begin decrypt and verify...");
//        //String decryptSignedMessage = new PGPDecryptAndVerify().decryptAndVerify(TestSecurityHelper.getEntityPGPPrivateKey(), TestSecurityHelper.getMyPGPPublicKey(), message, otherKeyPassphrase, symmetricKeyAlgorithm, hashingAlgorithm);
//        //System.out.println(decryptSignedMessage);
//        assertNotNull(signature, "Signature not null");
//    }
}
