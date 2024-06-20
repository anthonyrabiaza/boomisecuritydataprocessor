# Boomi Security Data Processor
>(aka Data Security Processor or Security Processor)

I wanted to share a solution I recently developed to simplify Secured Operations around Symmetric and Asymmetric Cryptography and Digital Signature using Public Key Infrastructure with the Dell Boomi AtomSphere Platform.
Dell Boomi Integration included out of the box Web of Trust functionality with PGP (Pretty Good Privacy) and this extension is adding:
- Support of X.509:
  - For Signing and Signature validation
  - For Encryption and Decryption
    - Payload direct encryption/decryption
    - S/MIME encryption/decryption
- Support of Javascript Object Signing and Encryption (JOSE):
  - For JSON Web Signature (JWS) Signing and Signature validation, for standard text payload and Java Web Token (JWT)
  - For JSON Web Encryption (JWE) Encryption and Decryption
- Support for PKCE
- Support for DPoP

The Boomi Security Processor will accelerate the Cryptographic operations and will wrap all the complex underlying operations: 

- Signing (Dell Boomi is the Sender on the following diagram) OR Validating Signature (Dell Boomi is the Receiver on the following diagram)

![Alt text](resources/signing.png?raw=true "BoomiSecurityDataProcessor") 

- Encrypting (Dell Boomi is the Sender on the following diagram) OR Decrypting  (Dell Boomi is the Receiver on the following diagram)
![Alt text](resources/encrypting.png?raw=true "BoomiSecurityDataProcessor") 

For more details on using the Security Data Processor go to [my blog](https://blog.antsoftware.org/boomi-advanced-security/)