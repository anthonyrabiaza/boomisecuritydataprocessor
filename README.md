# Boomi Security Data Processor
>(aka Data Security Processor or Security Processor)

I wanted to share a solution I recently developed to simplify Secured Operations around Symmetric and Asymmetric Cryptography and Digital Signature using Public Key Infrastructure with the Dell Boomi AtomSphere Platform.
Dell Boomi Integration included out of the box Web of Trust functionality with PGP (Pretty Good Privacy) and this extension is adding:
- Support of X.509:
  - For Signing and Signature validation
  - For Encryption and Decryption
- Support of Javascript Object Signing and Encryption (JOSE):
  - For JSON Web Signature (JWS) Signing and Signature validation, for standard text payload and Java Web Token (JWT)
  - For JSON Web Encryption (JWE) Encryption and Decryption

The Boomi Security Processor will accelerate the Cryptographic operations and will wrap all the complex underlying operations: 

- Signing (Dell Boomi is the Sender on the following diagram) OR Validating Signature (Dell Boomi is the Receiver on the following diagram)

![Alt text](resources/signing.png?raw=true "BoomiSecurityDataProcessor") 

- Encrypting (Dell Boomi is the Sender on the following diagram) OR Decrypting  (Dell Boomi is the Receiver on the following diagram)
  ![Alt text](resources/encrypting.png?raw=true "BoomiSecurityDataProcessor") 

## Exhaustive list of pre-configured Actions, Standards and Algorithms

| Actions                  | Standard | Algorithm     |
| --------------------------- | -------- | ------------- |
| Sign *or* Validate Signature | X.509    | SHA1withDSA   |
|                             | X.509    | SHA1withRSA   |
|                             | X.509    | SHA256withRSA |
| Sign *or* Validate Signature | JWS      | HS256         |
|                             | JWS      | HS384         |
|                             | JWS      | HS512         |
|                             | JWS      | RS256         |
|                             | JWS      | RS384         |
|                             | JWS      | RS512         |
|                             | JWS      | ES256         |
|                             | JWS      | ES384         |
|                             | JWS      | ES512         |
| Encrypt *or* Decrypt         | X.509    | AES/CBC/NoPadding   |
|          | X.509    | AES/CBC/PKCS5Padding |
|          | X.509    | AES/ECB/NoPadding |
|          | X.509    | AES/ECB/PKCS5Padding |
|          | X.509    | DES/CBC/NoPadding |
|          | X.509    | DES/CBC/PKCS5Padding |
|          | X.509    | DES/ECB/NoPadding |
|          | X.509    | DES/ECB/PKCS5Padding |
|          | X.509    | DESede/CBC/NoPadding                  |
|          | X.509    | DESede/CBC/PKCS5Padding |
|          | X.509    | DESede/ECB/NoPadding |
|          | X.509    | DESede/ECB/PKCS5Padding |
|          | X.509    | RSA/ECB/PKCS1Padding |
|          | X.509    | RSA/ECB/OAEPWithSHA-1AndMGF1Padding |
|          | X.509    | RSA/ECB/OAEPWithSHA-256AndMGF1Padding |
| Encrypt *or* Decrypt | JWE  | A128CBC-HS256 |
|          | JWE | A192CBC-HS384 |
|          | JWE | A256CBC-HS512 |
|          | JWE | A128GCM       |
|          | JWE | A192GCM       |
|          | JWE | A256GCM       |

## Getting Started

Please download the library [connector-archive](target/boomisecuritydataprocessor-0.17--car.zip?raw=true) and the connector descriptor [connector-descriptor](target/classes/connector-descriptor.xml?raw=true).

### Prerequisites in Boomi

#### Setup of the Connector

Please go to Setup>Account>Publisher and fill out the information.

And then, go to Setup>Development Resources>Developer and create a new Group. The two files to upload are the files you previous downloaded. For the Vendor Product Version, please mentioned the version of the Zip Archive.


#### Use of the Connector

The configuration is done by configuring the Connector (name Data Security Processor in the following capture):

![Alt text](resources/connector.png?raw=true "BoomiSecurityDataProcessor")

The Private and Public keys are standard Boomi Certificate created using:

- p12 or pfx file for Private Key
- cer or der for Public Key

Once the Connector configured, create an execute operation with one of the **four** operations:

- Sign
- Validate Signature
- Encrypt
- Decrypt

## Implementing Processes with the Security Data Processor

### Signing

The Following Process is the process using the *Sign* Operation:

![Alt text](resources/boomi_process_signing.png?raw=true "BoomiSecurityDataProcessor")

The Operation is configured as follow:

![Alt text](resources/boomi_operation_signing.png?raw=true "BoomiSecurityDataProcessor")

### Validating Signature
The Following Process is the process using the *Validate Signature* Operation:

![Alt text](resources/boomi_process_validating.png?raw=true "BoomiSecurityDataProcessor")

The Set Signature uses the following Document Property of the connector:

![Alt text](resources/boomi_operation_validating_document.png?raw=true "BoomiSecurityDataProcessor")

The Operation is configured as follow:

![Alt text](resources/boomi_operation_validating.png?raw=true "BoomiSecurityDataProcessor")

The output document will be a boolean providing the validity of the signature: 

![Alt text](resources/boomi_operation_output.png?raw=true "BoomiSecurityDataProcessor")

### Validating Signature of a Java Web Token (JWT)
The Following Process is the process using the *Validate Signature* Operation:

![Alt text](resources/boomi_process_validating_jwt.png?raw=true "BoomiSecurityDataProcessor")

The document in this example is defined as a Message and contained the full JWT Token (with multiple dots):

![Alt text](resources/boomi_message_jwt.png?raw=true "BoomiSecurityDataProcessor")

The Operation is configured as follow:

![Alt text](resources/boomi_operation_validating_jwt.png?raw=true "BoomiSecurityDataProcessor")

The output document will be a boolean providing the validity of the signature: 

![Alt text](resources/boomi_operation_output.png?raw=true "BoomiSecurityDataProcessor")

### Encrypting

The Following Process is the process using the *Encrypt* Operation:

![Alt text](resources/boomi_process_encrypting.png?raw=true "BoomiSecurityDataProcessor")

The Operation is configured as follow:

![Alt text](resources/boomi_operation_encrypting.png?raw=true "BoomiSecurityDataProcessor")

### Decrypting

The Following Process is the process using the *Decrypt* Operation:

![Alt text](resources/boomi_process_decrypting.png?raw=true "BoomiSecurityDataProcessor")

The Operation is configured as follow:

![Alt text](resources/boomi_operation_decrypting.png?raw=true "BoomiSecurityDataProcessor")