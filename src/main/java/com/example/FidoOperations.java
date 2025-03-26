package com.example;

import com.upokecenter.cbor.CBORObject;
import com.yubico.fido.metadata.MetadataBLOBPayloadEntry;
import com.yubico.fido.metadata.MetadataStatement;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.exception.RegistrationFailedException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class FidoOperations {

    public static void main(String[] args) {
        try {
            RelyingParty relyingParty = buildRelyingParty();
            processRegistration(relyingParty);


        } catch (Exception e) {
            System.err.println("Error during registration: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static RelyingParty buildRelyingParty() {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("se.curity")
                .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(new WebAuthnCredentialRepository())
                .attestationTrustSource(FidoMetaDataServiceProvider.getFidoMetadataService())
                .allowUntrustedAttestation(true)
                .origins(Set.of("https://localhost:8443"))
                .allowOriginPort(true)
                .build();
    }

    private static void processRegistration(RelyingParty relyingParty) throws IOException, RegistrationFailedException {
        
        // P-5 Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW" aka "RS256" algorithm, and check that server succeeds
        String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"tLgokKKkfUAxej0Uw1ds\",\"displayName\":\"Tony Alber\",\"id\":\"LNK_3vasHMXX91_ZlPFcmICwOdAC7id7fOwP8lweE2M\"},\"challenge\":\"nTLlD-r9M4xPcr4cyWru7OQ1CaGgBgKcRLgokfCrX_I\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        String responseJson = "{\"id\":\"_VS4SrMzurDRucxDd7752WA2epDtVYlL4E7INth4Xv0\",\"type\":\"public-key\",\"rawId\":\"_VS4SrMzurDRucxDd7752WA2epDtVYlL4E7INth4Xv0\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiblRMbEQtcjlNNHhQY3I0Y3lXcnU3T1ExQ2FHZ0JnS2NSTGdva2ZDclhfSSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQA3Hvy_dxdZQY9ekGfAcfSczCZJhzpPjJA6B1oC9W-9R7TYXIp5n7bJcvv0T-D8LwRtqgiDh9U8wGjfxcGVJzi3J-5R4rT8M3evLTDstdFrUBQ_2O7sW9GXQuPW4RpH_PItbuhWtOQZlk9NBwqpck9bYgJMQnkpnu0ugtxvWQKt99dwhlvLjWRkMhpchRb3zYorPoo35nJNwwqBZ5CKAffFuvxJ3l6zv-5-4pfApL4ydRlmDqAIOZT1cuDVlg-Pu9L38mx6Z08GD6bkB3cjGoOJbc3xEansrWcMMikTdPddKWrCJ8kDCtcgQg2dgpp9cL8FPVKGrTGoREZFicbVYi-oaGF1dGhEYXRhWQFoSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAAbJ3r2_0U3U6Nh3tKbjXds3UAIP1UuEqzM7qw0bnMQ3e--dlgNnqQ7VWJS-BOyDbYeF79pAEDAzkBACBZAQCd0X_ELke5zLydXuWmyafrTHQDiif9Y7YjATvdIONQ_ZNA_Y4MtiXZ49B93mO0c0uUls8x1t6CgYbFUGaRxoeTCZZMfKbndQkTTR9jMfz5JakpM4xwZMlslPV207XI1NOUbkj2sLV4LPpwfAG4zuVtJd2qEzLHi1Q7jj6jJQgCcXaT_JnzCPbCjMvSJB6x2VDehH4U1EJOknpadDf05bvffU-EQlBlsTzmA1R3wXj_L8dmeJvv6Jii6oKcyjy0-Iy1XbnAN4FTrMpzZ4JjUHRLxSxdwgY8E17jiT4KQup1z0PLo3rVkqCK1IuhfqzkIgNxqKeUYB4gXSbBycFf8pArIUMBAAGg\",\"transports\":[]},\"clientExtensionResults\":{}}";

        PublicKeyCredentialCreationOptions request = PublicKeyCredentialCreationOptions.fromJson(requestJson);
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential =
                PublicKeyCredential.parseRegistrationResponseJson(responseJson);

        RegistrationResult result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                .request(request)
                .response(credential)
                .build());

        printRegistrationResult(result, credential);
        //   validateIfRootCertificateIsPresentInAttestationTrustPath(result);
    }


    private static void printRegistrationResult(RegistrationResult result, PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential) {

        ByteArray aaguid = credential.getResponse()
                .getAttestation()
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .map(AttestedCredentialData::getAaguid)
                .orElseThrow(() -> new IllegalArgumentException("Missing AAGUID"));

        System.out.println("\nRegistration Result: Is Attestation Trusted? = " + result.isAttestationTrusted());
        System.out.println("Registration Result: Attestation Type = " + result.getAttestationType());
        System.out.println("Registration Result: Attestation Format = " + credential.getResponse().getAttestation().getFormat());
        System.out.println("Registration Result: Attested Credential AAGUID = " + aaguid);
        System.out.println("Registration Result: Attestation Statement = " + credential.getResponse().getAttestation().getAttestationStatement());

        result.getAttestationTrustPath().ifPresentOrElse(
                certs -> {
                    System.out.println("\nRegistration Result:  Attestation Trust Path Certs Chain: ");
                    certs.forEach(cert -> {
                                System.out.println("x509Certificate Subject = " + cert.getSubjectDN());
                                System.out.println("x509Certificate Issuer = " + cert.getIssuerDN());
                                System.out.println("\n");
                            }
                    );
                }
                ,
                () -> System.out.println("No attestation trust path found")
        );

        Set<MetadataBLOBPayloadEntry> matchedEntries =
                FidoMetaDataServiceProvider.getFidoMetadataService().findEntries(result);

        System.out.println("\nMetadata Service Matched Entries Size = " + matchedEntries.size());

        for (MetadataBLOBPayloadEntry entry : matchedEntries) {
            System.out.println("\n----------- Matched Metadata Entry ----------");
            System.out.println("AAID: " + entry.getAaid().orElse(null));
            System.out.println("AAGUID: " + entry.getAaguid().orElse(null));
            System.out.println("Description: " + entry.getMetadataStatement().map(MetadataStatement::getDescription).orElse(null));
            System.out.println("Metadata Statement : AAGUID = " + entry.getMetadataStatement().get().getAaguid());
            System.out.println("Metadata Statement : AttestationCertificateKeyIdentifiers = " + entry.getMetadataStatement().get().getAttestationCertificateKeyIdentifiers());
            System.out.println("Authenticator Version: " + entry.getMetadataStatement().map(MetadataStatement::getAuthenticatorVersion).orElse(null));

            // Log Root Certificates
            if (entry.getMetadataStatement().isPresent()) {
                System.out.println("Root Certificates: ");
                entry.getMetadataStatement().get().getAttestationRootCertificates()
                        .forEach(cert -> {
                            System.out.println("  - Subject: " + cert.getSubjectDN());
                            System.out.println("  - Issuer: " + cert.getIssuerDN());
                        });
            } else {
                System.out.println("No Metadata Statement found!");
            }
            System.out.println("-----------------------------------------------------");
        }

        if (result.getAttestationType().equals(AttestationType.SELF_ATTESTATION)) {
            boolean isSignatureValid = validateSignatureManuallyForSelfAttestation(credential);
            System.out.println("Is Signature Valid (SELF_ATTESTATION) ? = " + isSignatureValid);
        }

    }


    private static boolean validateSignatureManuallyForSelfAttestation(
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential) {
        try {
            AttestationObject attestationObject = credential.getResponse().getAttestation();
            ByteArray clientDataJSON = credential.getResponse().getClientDataJSON();
            AuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();

            AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData()
                    .orElseThrow(() -> new IllegalArgumentException("Missing AttestedCredentialData"));


            ByteArray credentialPublicKeyBytes = attestedCredentialData.getCredentialPublicKey();
            PublicKey publicKey = WebAuthnCodecs.importCosePublicKey(credentialPublicKeyBytes);

            CBORObject keyData = CBORObject.DecodeFromBytes(credentialPublicKeyBytes.getBytes());
            long keyAlgId = keyData.get(CBORObject.FromObject(3)).AsNumber().ToInt64IfExact();
            COSEAlgorithmIdentifier keyAlg = COSEAlgorithmIdentifier.fromId(keyAlgId)
                    .orElseThrow(() -> new IllegalArgumentException("Unsupported COSE algorithm identifier: " + keyAlgId));

            long sigAlgId = attestationObject.getAttestationStatement().get("alg").asLong();
            COSEAlgorithmIdentifier sigAlg = COSEAlgorithmIdentifier.fromId(sigAlgId)
                    .orElseThrow(() -> new IllegalArgumentException("Unsupported COSE algorithm identifier: " + sigAlgId));

            if (!Objects.equals(keyAlg, sigAlg)) {
                throw new IllegalArgumentException(String.format(
                        "Key algorithm and signature algorithm must be equal, was: Key: %s, Sig: %s", keyAlg, sigAlg));
            }

            ByteArray signedData = authenticatorData.getBytes().concat(clientDataJSON);
            ByteArray signature = new ByteArray(attestationObject.getAttestationStatement().get("sig").binaryValue());

            System.out.println("Self Attestation Validation : Signature Algorithm = " + sigAlg);
            System.out.println("Self Attestation Validation : Key Algorithm = " + keyAlg);
            System.out.println("Self Attestation Validation : sigAlgId  = " + sigAlgId);
            System.out.println("Self Attestation Validation : authenticatorData: " + authenticatorData.getBytes().getBase64());
            System.out.println("Self Attestation Validation : clientDataJSON: " + clientDataJSON.getBase64());
            System.out.println("Self Attestation Validation : signedData: " + signedData.getBase64());
            System.out.println("Self Attestation Validation : signature: " + signature.getBase64());
            System.out.println("Self Attestation Validation : COSE Key Data: " + keyData);
            //    debugSignatureData(authenticatorData.getBytes(), clientDataJSON, signature, publicKey);
            return Crypto.verifySignature(publicKey, signedData, signature, keyAlg);

        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error during signature validation", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


//    private static void validateIfRootCertificateIsPresentInAttestationTrustPath(RegistrationResult result) {
//        // Get the certificates from the attestation trust path
//        Optional<List<X509Certificate>> trustPathOptional = result.getAttestationTrustPath();
//
//        if (trustPathOptional.isPresent()) {
//            List<X509Certificate> trustPath = trustPathOptional.get();
//
//            // Ensure there's more than one certificate (root is usually the last one)
//            if (!trustPath.isEmpty()) {
//                // Check if last certificate is self-signed (root CA)
//                X509Certificate lastCert = trustPath.get(trustPath.size() - 1);
//                // Check if last certificate is self-signed (root CA)
//                if (isSelfSigned(lastCert)) {
//                    throw new RuntimeException("Attestation statement contains a root certificate, which is not allowed.");
//                }
//            }
//        }
//
//    }
//
//    /**
//     * Checks if an X.509 certificate is self-signed (i.e., a root certificate).
//     */
//    private static boolean isSelfSigned(X509Certificate cert) {
//        try {
//            cert.verify(cert.getPublicKey()); // If this succeeds, it's self-signed
//            return true;
//        } catch (Exception e) {
//            return false;
//        }
//    }


//    private static void debugSignatureData(ByteArray authenticatorData, ByteArray clientDataJSON, ByteArray signature, PublicKey publicKey) throws Exception {
//        byte[] signedDataBytes = authenticatorData.concat(clientDataJSON).getBytes();
//        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
//        byte[] hash = sha256.digest(signedDataBytes);
//        System.out.println("SHA256(authenticatorData || clientDataJSON): " + new ByteArray(hash).getBase64());
//        Signature sig = Signature.getInstance("SHA256withRSA");
//        sig = Signature.getInstance("SHA256withRSA");
//        sig.initVerify(publicKey);
//        sig.update(hash);
//        boolean isValid = sig.verify(signature.getBytes());
//        System.out.println("Manual Signature Verification (Hashed Data): " + isValid);
//
//
//        Signature sig1 = Signature.getInstance("SHA256withRSA");
//        sig1.initVerify(publicKey);
//        sig1.update(signedDataBytes);
//        boolean isValid1 = sig1.verify(signature.getBytes());
//        System.out.println("Manual Signature Verification (Raw Data): " + isValid1);
//    }

}
