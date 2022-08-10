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
| --------------------------- |----------| ------------- |
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
| Encrypt *or* Decrypt | JWE      | A128CBC-HS256 |
|          | JWE      | A192CBC-HS384 |
|          | JWE      | A256CBC-HS512 |
|          | JWE      | A128GCM       |
|          | JWE      | A192GCM       |
|          | JWE      | A256GCM       |
| Encrypt *or* Decrypt | S/MIME   | TRIPLEDES |
|          | S/MIME      | DES |
|          | S/MIME      | RC_2_128 |
|          | S/MIME      | RC_2_64       |
|          | S/MIME      | RC_2_40       |
|          | S/MIME      | AES_128       |
|          | S/MIME      | AES_192       |
|          | S/MIME      | AES_256       |

## Getting Started

Please download the library [connector-archive](target/boomisecuritydataprocessor-0.21--car.zip?raw=true) and the connector descriptor [connector-descriptor](target/classes/connector-descriptor.xml?raw=true).

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

## Implementing fields encryption/decryption in Map

We can use the Get operation of Security Processor to encrypt and decrypt fields with Salting (put 0 for the value of *salt size* to disable salting).

### Creation of the Security Operation

Create a new Connector Operation with "GET" type and click on "Import"

![Alt text](resources/boomi_operation_encrypting_field_a.png?raw=true "BoomiSecurityDataProcessor")

Select the object type (here Get_Encrypt)

![Alt text](resources/boomi_operation_encrypting_field_b.png?raw=true "BoomiSecurityDataProcessor")

Click on Next

![Alt text](resources/boomi_operation_encrypting_field_c.png?raw=true "BoomiSecurityDataProcessor")

Validate that the Response Profile is created and make sure that its type is Get_Encrypt if Action = Encrypt.

For Action = Decrypt, please use Get_Decrypt object during the import.

![Alt text](resources/boomi_operation_encrypting_field_d.png?raw=true "BoomiSecurityDataProcessor")

### Operation Key Alias

The value for Key Alias is the *alias name* of the entry value from the Private or Private Key.

There are multiple ways to get this value.

1. Using keytool

```shell
keytool -v -list -keystore boomi.pfx 
Enter keystore password:  
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: 1
```
2. Using keystore explorer

![Alt text](resources/keystore-explorer.png?raw=true "BoomiSecurityDataProcessor")

In our case, we have to put **1** as *Key Alias*.

For public key, use the value: **publickey_0**

### Map with field encryption

In your Map shape:

- add a function
- select Connector Call
- use the existing Connection
- select the previous created Operation
- on Input, select ID
- on Output, select the corresponding object (encryptedValue or decryptedValue)

![Alt text](resources/boomi_operation_encrypting_field_e.png?raw=true "BoomiSecurityDataProcessor")

Validate the input and output of the Function

![Alt text](resources/boomi_operation_encrypting_field_f.png?raw=true "BoomiSecurityDataProcessor")

### Overall Process using the map with field encryption

Example of process reading values in JSON and writing to a DB

![Alt text](resources/boomi_process_encrypting_field.png?raw=true "BoomiSecurityDataProcessor")

Output in the DB , **please make sure that the size of the column is wide enough** (in our example a field of 16 chars + salt of 8 chars is converted to a string of 344 chars)

![Alt text](resources/boomi_process_encrypting_field_db.png?raw=true "BoomiSecurityDataProcessor")