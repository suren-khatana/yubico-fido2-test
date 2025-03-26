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

        // F-10 Send ServerAuthenticatorAttestationResponse with FULL "packed" attestation, with attStmt.x5c containing full chain, and check that server returns an error
        // String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"_PdhNkUCUFsVqhnZj4l0\",\"displayName\":\"Josiah Turman\",\"id\":\"7NjZREdxSy5R_DzJlnopnr1Vzp47nuHQu7VeTwEvx5Y\"},\"challenge\":\"3PEHiVbyqR7amlKDx3i11jEAihsXmUivbrrBisvlm5o\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        // String responseJson = "{\"id\":\"MZovlmHrwLZrDrufaa9mdtXgElr7I8rzKqnh90N-8IA\",\"type\":\"public-key\",\"rawId\":\"MZovlmHrwLZrDrufaa9mdtXgElr7I8rzKqnh90N-8IA\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiM1BFSGlWYnlxUjdhbWxLRHgzaTExakVBaWhzWG1VaXZicnJCaXN2bG01byIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAJdkaqqr6HddHVJdefdCRZ-z7T10kIulOevKJ6VIKY6LAiBjrnGsYVfAowKsZ93SP4oj63_eGDMY5wJtfa9lpgVKZmN4NWODWQKSMIICjjCCAjSgAwIBAgIBATAKBggqhkjOPQQDAjCBrzEmMCQGA1UEAwwdRklETzIgSU5URVJNRURJQVRFIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzNzQxWhcNMjgwNTIwMTQzNzQxWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEutlirPGtUi-a-woMkhwX2-s6mZPQpKNmY77E9cvyGvuAZGllHFGRg_R8kQ_MKjRlMrcP68cW2x0OAb1XbilIZKMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUSlTlBtKRRE9tDzNd1v3HRmy5X1QwCgYIKoZIzj0EAwIDSAAwRQIhALlbNrRzfaOsENMNvvXrleUEJ0JaRJV_O-GGodN_J-pFAiBNC6zAOECkfCpP9fpbxphxyp6cpv0coXwM1pGEczcpeFkENTCCBDEwggIZoAMCAQICAQIwDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODA3MjMxNDI5MDdaFw00NTEyMDgxNDI5MDdaMIGvMSYwJAYDVQQDDB1GSURPMiBJTlRFUk1FRElBVEUgcHJpbWUyNTZ2MTExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNxBHd9VbX9Nc4ypdRR6VXH0YwApI9ZvtHtel4cgcFkFDsnOh6lvNFeK1N0ItMJ81eksTUbolFyy0-Zf20tJefOjLzAtMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGfBGZKQW_VdAMHWIQ6MLXYhkkfAMA0GCSqGSIb3DQEBCwUAA4ICAQALmC6ns1S7Byd2J-_l3CVnoYhI9MRyJB0zGY2j2cT0FEA7Zu1DQN0l2J8DwadBB3b10iCTxTjxa5xjirO69FlorrPoAitTZsBSUmsqeVNm-N2IzeiJNj1ZOIH17J-Yr9mAS_tb0MQVbu-uHfb6mNI0XVXLG4wSmdrVfqzKq00NUb7DRguN2ReLRyK5EnLRD0D3S-YwqADGCdF8KiXlpBSUelkxOIr7w4KnyxKirTlA3f2LLfi7gB4oZRZ64qNgTA2yAqCf6_X4DV1tTDZxZiDnc6Lmb8NAuW35azWGiS7BfEJ6RoG-J4H2e7Xd9he_tKSDC5Y83DIU-VCRakg-Bv15kwTeSdSInYQBLVQTuStpY2DdxA7a_q1jbj7n4WYTK5aKcYKGsezBPSxi2aFAaVZrRsJX18Qsvr1sI7rhGJah6cuyJfXmGaYLv5lsX0PVUePUEdH16KgBlRWicSIMlJke1XFeWZTeNAGGsQ_O0XlGfrvR3Or8Tgcs9_Nuspb4vYXaL5YRYXty2Jw1UEEtdQewUC8Zgyq_sMTTMMZpnsv6NciNIKITYiOLEKExjD9oVjCbHQ3rK5d4kNi7x8JJc4pM9HplGwsJDfy1cVJBHKfVPkWC_F2ztDazGC1VcI3LwUyih_buCMy7mLikC3aV1cQ7HXMjY_42_oYXFjZT8G1cg1kFxDCCBcAwggOoAgkAjZtbueqEcF0wDQYJKoZIhvcNAQELBQAwgaExGDAWBgNVBAMMD0ZJRE8yIFRFU1QgUk9PVDExMC8GCSqGSIb3DQEJARYiY29uZm9ybWFuY2UtdG9vbHNAZmlkb2FsbGlhbmNlLm9yZzEWMBQGA1UECgwNRklETyBBbGxpYW5jZTEMMAoGA1UECwwDQ1dHMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDAeFw0xODAzMTYxNDM1MjdaFw00NTA4MDExNDM1MjdaMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9dVOcgCFSzKy98UvLvMrDEnTpA3qEzvkXAMvrl16epOEgvozst-4CAhLWCPjCkFdRDHjDH96zNbnmQDt4jxWtDRHYv6EO56ZxowTSPMDMw_BXzXuq1rc5A2h6bGVv__zMFg6RsiUfl8o3KulOL0vW0us2e47JcNDnM8eFLGIDrCFF0kgWhjq0W8SfyQuYJw2BGL7TTPjwz3MyzSgMoXbwWVjVh6-zGdD-U3iUHF7AKEoUV9mPFPH0TSZu0nohSgz9DZ_0CsTkre8xj-MbfZzGrBNatmU3Wq9vltdwkc9-0SNGVqav_mKrqBG2e1I-zZgU3KoW9utJ5gxEdhacMGMD0mq5PdiGW2pqMwfHezhCNYyYLK4yYSmp9BJkWllQaR0-MWCnRLu69PUtCYSslPudlg5plUEzKWC65uF5e4Uccj8gWJGpa6M7Bpj7PL5YTat1bFW8gUjEqRJlGngGuyyxPf1YdGoCS1RR4dXoWCiacx55pgV1KsdBc92n5g5tTV9LK9zv-sSMdVUk1Yk9yjcQWKVR9aoxwEy87sXFppvu-X3CTIj2D0jF1ZkW90NZfdQDOAQXloZT9xW3O4A8tK_rO5tLBkuj09idqxqINq1MZyfswjNdTOw3jtFzNp58uLkWDz5PcNhF8377Xb4nmFP-UQeEQ5uUxsR4Rl1WVIGnOQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQBbdlxnd5ORqWztRFJt7utM09XxOruqTrHKdeepOVZ7B4Gh0R3SADzS3izZke8uTp6124ddwqxsFNavOI4yV6b_r9eMVAnOYtNcqKRU0BS6-AOzR6dpzWHzYYSFUhQIFuNxH5SX5WyxHpQic8S5Vm-QaA7GXnjZhELFyDNZidukd69Hc7BwW9LsvvCzUdYHVanY4QvAS8t4IePgVroncmTbdOy73g7EhVua3I-cEa0sfYVzyMlaY0EpYzb2OzFU6LqiczQAEDLEypFz5E15XQqKfUKPVD5B0UZtJeyy7XWjqF63LdGJqHH_M8X_WxTYsPX-FkWEDOrDIc7fPrP6A4paOEIXFIHiRIhDxEousp2E1etkhwOHjLp1CeXZQmkZxYkfQ0yJhWuSEc4nt9uv51v0jwminP8qxSIoTDIyaEgD4aU2_yushzlBvK_iokLrezc6hld9NaUPbutnRi-TotVV5ghZRNq2pmbNeQTTlMgKNggW0SYN4ynHbv_EAuqI4w70POt_uyz7Z--MCQuUaVCbEtBoUFoKuaQFzt8AOtVKG8YujJDqQgtMwVsf3eAqqUuI-IRYMVgU11-PIoT7voSMSBfwMW6rT76izBMVv8WSE5-gK6VskPXuElFa959xd92qdV3Q8mdL8BXJtfCUALbL10-qgi61jl5x1IH5__lYrmhhdXRoRGF0YVilSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAALjJq3PAM70bQk5KY1sSoSnIAIDGaL5Zh68C2aw67n2mvZnbV4BJa-yPK8yqp4fdDfvCApQECAyYgASFYIKzeL1UbTslNy2Y57SlcQrWRxO3VEfnZIqmYYlNSqeGyIlggvh86aXAPD_Y7xaz7K4ynceZGkp6_fYoe9kg6uKSCoRGg\",\"transports\":[]},\"clientExtensionResults\":{}}";

        // F-2 Send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation for metadata from MDS3 who's signature can not be verified, and check that serve returns an error
        // String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"_SFqonwWe-qDJ7_IZCrK\",\"displayName\":\"Josiah Turman\",\"id\":\"uSRTz9F3zmwx-vvh7RnYbZMkZo8vYrBAvkeeCpJbPTg\"},\"challenge\":\"QS4zXzMvKVPW8lJbu27Il4taoNwTtebUuO9wLH-lVdY\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        // String responseJson = "{\"id\":\"AnI7j95SugyXBDp4xUig90re8_bvc3KTAl7h1lTiiNU\",\"type\":\"public-key\",\"rawId\":\"AnI7j95SugyXBDp4xUig90re8_bvc3KTAl7h1lTiiNU\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiUVM0elh6TXZLVlBXOGxKYnUyN0lsNHRhb053VHRlYlV1Tzl3TEgtbFZkWSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhANOr8GtBHfPQkqZThYmHuWj4Db05Nam4Nhhgpf0wwUQEAiACBnWr4TQlEuYsrfeghPda6IZHxHyALhp-OOo-kfKH32N4NWOBWQRFMIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf-CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD-74OS8fZRgZiNf9EDGAYiHh0-CspfBWd20zCIjlCdDBcyhwq3PLJ65JC_og3CT9AK4kvks4DI-01RYxNv9S8Jx1haO1lgU55hBIr1P_p21ZKnpcCEhPjB_cIFrHJqL5iJGfed-LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb-RGG2TYURFIGYGijsii093w0ZMBOfBS-3Xq_DrHeZbZrrNkY455gJCZ5eV83Nrt9J9_UF0VZHl_hwnSAUC_b3tN_l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM_itCjdBvAYt4QCT8dX6gmZiIGR2F_YXZAsybtJ16pnUmODVbW80lPbzy-PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo-US-nIzG5XZmOeu4Db_Kw_dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS_Aolsz7HGhhdXRoRGF0YVilSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAAEJ6F0eFKUUOUtsN2yk29fiwAIAJyO4_eUroMlwQ6eMVIoPdK3vP273NykwJe4dZU4ojVpQECAyYgASFYIL6PQDtcHpgK_HCW0A4mm3tRO0XP3BrRb3xdKg8AoKUWIlgghpNcQx-lq_JBJTH2QZBvlvomF8DHaAsj_JrQmZHSQ3Cg\",\"transports\":[]},\"clientExtensionResults\":{}}";


        // F-12 Send ServerAuthenticatorAttestationResponse with attestationObject.authData AttestationData contains leftover bytes, and check that server returns an error
        //String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"oI9GPT9k-6blKXcEIRMK\",\"displayName\":\"Leona Grayson\",\"id\":\"PkDLMplb8lJdxFUbouAp1u90cfzqXEjg4f3KolsKFK8\"},\"challenge\":\"Pl9Pobj-IUrrjp0a-Ye7rCgpYsE6zzCVboqfP5WmQx4\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        //String responseJson = "{\"id\":\"sct1kn7YegCbuo6nzseEPOCMcfJfZBmj642AYfpY-LY\",\"type\":\"public-key\",\"rawId\":\"sct1kn7YegCbuo6nzseEPOCMcfJfZBmj642AYfpY-LY\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiUGw5UG9iai1JVXJyanAwYS1ZZTdyQ2dwWXNFNnp6Q1Zib3FmUDVXbVF4NCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAKtloP158cuANxVD0DO-C0lV-gHiZOLlBj_wsHpo18KNAiAp7kSnp5yleggp_MhboSlh_KGrnCHbxZ1lEilgJFy9FWN4NWOBWQRFMIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf-CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD-74OS8fZRgZiNf9EDGAYiHh0-CspfBWd20zCIjlCdDBcyhwq3PLJ65JC_og3CT9AK4kvks4DI-01RYxNv9S8Jx1haO1lgU55hBIr1P_p21ZKnpcCEhPjB_cIFrHJqL5iJGfed-LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb-RGG2TYURFIGYGijsii093w0ZMBOfBS-3Xq_DrHeZbZrrNkY455gJCZ5eV83Nrt9J9_UF0VZHl_hwnSAUC_b3tN_l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM_itCjdBvAYt4QCT8dX6gmZiIGR2F_YXZAsybtJ16pnUmODVbW80lPbzy-PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo-US-nIzG5XZmOeu4Db_Kw_dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS_Aolsz7HGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAAVDJq3PAM70bQk5KY1sSoSnIAILHLdZJ-2HoAm7qOp87HhDzgjHHyX2QZo-uNgGH6WPi2pQECAyYgASFYII0sx6QKx4JC1pYyytb4305a5ffFAXf_WyWPma00FdY0IlggRgPKwqdxcfEKrrIVuAJ0brEckdw60UBNDXR8GJr6ozmg2bPK91t1Uruh22Xd2sgFgz9n59mXyiTYc4HbP4ugKLo\",\"transports\":[]},\"clientExtensionResults\":{}}";


        // P-5 Send a valid ServerAuthenticatorAttestationResponse with SELF "packed" attestation, for "ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW" aka "RS256" algorithm, and check that server succeeds
        // String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"nj9sz8DW1H6LW72oMbtj\",\"displayName\":\"Latosha Sabatini\",\"id\":\"_G2WkAMo8GQQI4SMo1iryqPJ_sw52rVCI4goKznzYmc\"},\"challenge\":\"043K3C4WO9fvl9HoPMGG_cV2rX1cDIh2rMtmVstrPrM\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        // String responseJson = "{\"id\":\"cn7CaQVUmBDcqNpz-cCD0d5vmMFYslziAeklk6bcemA\",\"type\":\"public-key\",\"rawId\":\"cn7CaQVUmBDcqNpz-cCD0d5vmMFYslziAeklk6bcemA\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiMDQzSzNDNFdPOWZ2bDlIb1BNR0dfY1YyclgxY0RJaDJyTXRtVnN0clByTSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAGNzaWdZAQBwJGeage9pyIEsGh1nuRucnefGaVyz-Tp3xDBKQU9cfbyyYHNUOuaMFZ05Ns-iUtNqUdXpnlQXlzDJpaw_Z5plQD2Z-jpUL9dkDcfADtBBtk-JXmzV6jWW--Ue32sKv49O17JzA_brYmqTcc8vEsFI3hSWvDE3ag2u56O3FhpTZ3xoa3PglqmByx5_mSwlT-fZZL_FG9DdOlrDrxLsrZVusvQM6OJIHG1iTR82QXm3OImyMt0uKiBLgcMnI_c3BUtk8rkqhbDVXg28odqLACs_K46clCf_usuhyfvxplofbmR2ndUxxMpu2kYt336yAfM_brDOStZqjKk5kAdGlBqAaGF1dGhEYXRhWQFoSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAAdp3r2_0U3U6Nh3tKbjXds3UAIHJ-wmkFVJgQ3Kjac_nAg9Heb5jBWLJc4gHpJZOm3HpgpAEDAzkBACBZAQDkuNBK-6VRCowuPdfU-Ol301D8pLW7iaxsBbcwefnDNBo8amf4bvpTs6TPADfrgUGpnGeGQIqUqU6Ny1oVB-tF7hFfJAd5g5YoKh9EuwN_hKHDr6hRUnLStEovwAPMc2LSbJO8zhg7hwDr0g9SkxqHU0pSXAWjZvf_pp-dlGQxkX-vp37LjwtgpwTGevwuv5tXneZAIMDWKQUgT65J_SwRUJl9ylC_pkAJ72cTeu92XELv1oYvcSo8Lt1DKRizVVIBBvp6tKgLY033ErAXZNu0jJuL3vb8_NArNFgZ4CQT9nrXbcnN8H8zWV81hnW-2uPlVX86HVvEg5ofgkQM0pOJIUMBAAGg\",\"transports\":[]},\"clientExtensionResults\":{}}";


        // P-2 Send a valid ServerAuthenticatorAssertionResponse with authenticatorData.flags.UV is set, for userVerification set to "required", and check that server succeeds (Valid attestation)
        // String requestJson="{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"C4rnVH0YWCv9feIYM7et\",\"displayName\":\"Stasia Britain\",\"id\":\"GVd0Yf9wjWb1veMae8zBvDboZf8hKBZZtquQk48fEXs\"},\"challenge\":\"QoZp-xC_mHQGzu5Zcq5GGG3n04Yz52Tk-fY-0QEbM2Y\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        // String responseJson="{\"id\":\"CziHEOEEtsyPai-aIoWgiGFZQXaNFu121WB-xPxyD7k\",\"type\":\"public-key\",\"rawId\":\"CziHEOEEtsyPai-aIoWgiGFZQXaNFu121WB-xPxyD7k\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiUW9acC14Q19tSFFHenU1WmNxNUdHRzNuMDRZejUyVGstZlktMFFFYk0yWSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgQlZOw7Ui7rw1OFCRJXU6zc8qK2jt5LvrKlQEi1SL4WoCIQDjT9I7k20_JpntNajj8J0KfF8qYS9gxtfCOMOzBk-j5GN4NWOBWQRFMIIEQTCCAimgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDUyMzE0Mzk0M1oXDTI4MDUyMDE0Mzk0M1owgcIxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQBgNVBAcMCVdha2VmaWVsZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE86Xl6rbB-8rpf232RJlnYse-9yAEAqdsbyMPZVbxeqmZtZf8S_UIqvjp7wzQE_Wrm9J5FL8IBDeMvMsRuJtUajLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFFZN98D4xlW2oR9sTRnzv0Hi_QF5MA0GCSqGSIb3DQEBCwUAA4ICAQCH3aCf-CCJBdEtQc4JpOnUelwGGw7DxnBMokHHBgrzJxDn9BFcFwxGLxrFV7EfYehQNOD-74OS8fZRgZiNf9EDGAYiHh0-CspfBWd20zCIjlCdDBcyhwq3PLJ65JC_og3CT9AK4kvks4DI-01RYxNv9S8Jx1haO1lgU55hBIr1P_p21ZKnpcCEhPjB_cIFrHJqL5iJGfed-LXni9Suq24OHnp44Mrv4h7OD2elu5yWfdfFb-RGG2TYURFIGYGijsii093w0ZMBOfBS-3Xq_DrHeZbZrrNkY455gJCZ5eV83Nrt9J9_UF0VZHl_hwnSAUC_b3tN_l0ZlC9kPcNzJD04l4ndFBD2KdfQ2HGTX7pybWLZ7yH2BM3ui2OpiacaOzd7OE91rHYB2uZyQ7jdg25yF9M8QI9NHM_itCjdBvAYt4QCT8dX6gmZiIGR2F_YXZAsybtJ16pnUmODVbW80lPbzy-PUQYX79opeD9u6MBorzr9g08Elpb1F3DgSd8VSLlsR2QPllKl4AcJDMIOfZHOQGOzatMV7ipEVRa0L5FnjAWpHHvSNcsjD4Cul562mO3MlI2pCyo-US-nIzG5XZmOeu4Db_Kw_dEPOo2ztHwlU0qKJ7REBsbt63jdQtlwLuiLHwkpiwnrAOZfwbLLu9Yz4tL1eJlQffuwS_Aolsz7HGhhdXRoRGF0YVilSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAAIjJq3PAM70bQk5KY1sSoSnIAIAs4hxDhBLbMj2ovmiKFoIhhWUF2jRbtdtVgfsT8cg-5pQECAyYgASFYIBquPmSyoIJHxTj_MEiuXaPDBJPBQFCvCKfr3ihnFz1FIlggCY3KIFpkWXhNl4QL1M7KwSLnIPYKTlapZQ3SllEdAAmg\",\"transports\":[]},\"clientExtensionResults\":{}}";


        // F-1 Send ServerAuthenticatorAttestationResponse with SELF "packed" attestation, and with attStmt.sig contains an invalid signature, and check that server returns an error
        // String requestJson="{\"attestation\":\"direct\",\"errorMessage\":\"\",\"authenticatorSelection\":{\"userVerification\":\"preferred\",\"residentKey\":\"preferred\"},\"excludeCredentials\":[],\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"extensions\":{\"example.extension.bool\":true},\"challenge\":\"0gQ6V7G2_4adiyOtAaYLPtF5ej5QCXmdFUzFY5cpwKs\",\"user\":{\"name\":\"xAK13oCDffB0oLZmljXh\",\"displayName\":\"Shenika Olin\",\"id\":\"y3VWMSOFfIRg7Zt1SO0EM7-nqT4-S4mzDmDRkkqSrh4\"},\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"status\":\"ok\"}";
        //String responseJson="{\"id\":\"zUhtOL_ir8gB2-jQyp2qxTfNzdoXEomBdtHDp0e6iUY\",\"rawId\":\"zUhtOL_ir8gB2-jQyp2qxTfNzdoXEomBdtHDp0e6iUY\",\"response\":{\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEehVSQKbgmo-rCquye5JkSVPEywqRdGKm7Ii4rQAiEAmli86RXGPzaJGVJ7z3k7NxsH3a74MjpIwVr-21WCBjNTMyEcLIVOPmhhdXRoRGF0YVilSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PBAAAAGSsuy7RZtET6ho2gckhdiuAAIM1IbTi_4q_IAdvo0MqdqsU3zc3aFxKJgXbRw6dHuolGpQECAyYgASFYIAILLAXb7HQ_hZ6WqAd4pxol_qJD3DYztSeYLbP_cV-jIlggnIBwEMSB447a8gz-2thCglB3nywMDV97-Xej0BdHcJOg\",\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiVElhV0FLOENaX2JET0cxXzlUcDdqeHVqdlA0eWRpMzgzaV9ZMzJWcFZOcyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\"},\"getClientExtensionResults\":{},\"type\":\"public-key\"}";

        // F-2 Send ServerAuthenticatorAttestationResponse with SELF "packed" attestation, that contains full attestation, and check that server returns an error
        // String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"xh5dzL-wf9WbzknqEqX1\",\"displayName\":\"Deandra Sauer\",\"id\":\"5RKymK5FweoIcU8YitzE3Zcr3iVXbGEg4eoaw1We-z4\"},\"challenge\":\"7ueilLajvxXjp352ot6hk-ytjhM03KvrzgQpkG3fF4E\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        // String responseJson = "{\"id\":\"PmNB2WF2IWcCDqCrl271wN5hbAs8awlSd-UFEQbn7to\",\"type\":\"public-key\",\"rawId\":\"PmNB2WF2IWcCDqCrl271wN5hbAs8awlSd-UFEQbn7to\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiN3VlaWxMYWp2eFhqcDM1Mm90NmhrLXl0amhNMDNLdnJ6Z1Fwa0czZkY0RSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgaKeCOTL6Epwxdw7MifHKXKeZ_IAO4cTPYWgb66C8cn0CIHkENqXrRqMj02baMRvHG27swrQqAsIj5YL3PlS0SiXPY3g1Y4FZBEUwggRBMIICKaADAgECAgEBMA0GCSqGSIb3DQEBCwUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzOTQzWhcNMjgwNTIwMTQzOTQzWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzpeXqtsH7yul_bfZEmWdix773IAQCp2xvIw9lVvF6qZm1l_xL9Qiq-OnvDNAT9aub0nkUvwgEN4y8yxG4m1RqMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUVk33wPjGVbahH2xNGfO_QeL9AXkwDQYJKoZIhvcNAQELBQADggIBAIfdoJ_4IIkF0S1Bzgmk6dR6XAYbDsPGcEyiQccGCvMnEOf0EVwXDEYvGsVXsR9h6FA04P7vg5Lx9lGBmI1_0QMYBiIeHT4Kyl8FZ3bTMIiOUJ0MFzKHCrc8snrkkL-iDcJP0AriS-SzgMj7TVFjE2_1LwnHWFo7WWBTnmEEivU_-nbVkqelwISE-MH9wgWscmovmIkZ9534teeL1K6rbg4eenjgyu_iHs4PZ6W7nJZ918Vv5EYbZNhREUgZgaKOyKLT3fDRkwE58FL7der8Osd5ltmus2RjjnmAkJnl5Xzc2u30n39QXRVkeX-HCdIBQL9ve03-XRmUL2Q9w3MkPTiXid0UEPYp19DYcZNfunJtYtnvIfYEze6LY6mJpxo7N3s4T3WsdgHa5nJDuN2DbnIX0zxAj00cz-K0KN0G8Bi3hAJPx1fqCZmIgZHYX9hdkCzJu0nXqmdSY4NVtbzSU9vPL49RBhfv2il4P27owGivOv2DTwSWlvUXcOBJ3xVIuWxHZA-WUqXgBwkMwg59kc5AY7Nq0xXuKkRVFrQvkWeMBakce9I1yyMPgK6XnraY7cyUjakLKj5RL6cjMbldmY567gNv8rD90Q86jbO0fCVTSoontEQGxu3reN1C2XAu6IsfCSmLCesA5l_Bssu71jPi0vV4mVB9-7BL8CiWzPscaGF1dGhEYXRhWKVJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY8EAAAAaKy7LtFm0RPqGjaBySF2K4AAgPmNB2WF2IWcCDqCrl271wN5hbAs8awlSd-UFEQbn7tqlAQIDJiABIVggmDP1Jsn4CHl94ntGwX_gNrDJc0dXtvmiYcVPCVTWvx0iWCAWGm1BVdpAxTcRfntiKfUlZotBDc3gQLG0dfRM-pio1qA\",\"transports\":[]},\"clientExtensionResults\":{}}";


        // F-2 For MDS blob whose signature cannot be verified, send a valid ServerAuthenticatorAttestationResponse with FULL "packed" attestation by authenticator from that blob and check that server returns an error.
        //   String requestJson = "{\"rp\":{\"name\":\"se.curity\",\"id\":\"localhost\"},\"user\":{\"name\":\"DVYZdv4TieJOHCKmZdoj\",\"displayName\":\"Star Euell\",\"id\":\"0r3p5i8lApahfzDG0ORz1aO7mJJctq5zNTkhKpHiGPI\"},\"challenge\":\"nuVQlt9nR5Si6Dprhv5rP943T4a2T_a9I_9EJBKLXiM\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-35,\"type\":\"public-key\"},{\"alg\":-36,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"},{\"alg\":-258,\"type\":\"public-key\"},{\"alg\":-259,\"type\":\"public-key\"},{\"alg\":-65535,\"type\":\"public-key\"}],\"hints\":[],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}";
        //   String responseJson = "{\"id\":\"XsHlGa0A3EdEbxHSQNVKIxHRxYZ8O-INNzeeANMAY8s\",\"type\":\"public-key\",\"rawId\":\"XsHlGa0A3EdEbxHSQNVKIxHRxYZ8O-INNzeeANMAY8s\",\"response\":{\"clientDataJSON\":\"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoibnVWUWx0OW5SNVNpNkRwcmh2NXJQOTQzVDRhMlRfYTlJXzlFSkJLTFhpTSIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ\",\"attestationObject\":\"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgcSlI3cQDFARtmOn4M6lLXvZuVzzXO9As9aAXcHKZLiECIFpcq850DjGENtlnW_Swrtv1rdazIEjTeq2iPbuqJJHoY3g1Y4FZBEUwggRBMIICKaADAgECAgEBMA0GCSqGSIb3DQEBCwUAMIGhMRgwFgYDVQQDDA9GSURPMiBURVNUIFJPT1QxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTIzMTQzOTQzWhcNMjgwNTIwMTQzOTQzWjCBwjEjMCEGA1UEAwwaRklETzIgQkFUQ0ggS0VZIHByaW1lMjU2djExMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzpeXqtsH7yul_bfZEmWdix773IAQCp2xvIw9lVvF6qZm1l_xL9Qiq-OnvDNAT9aub0nkUvwgEN4y8yxG4m1RqMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUVk33wPjGVbahH2xNGfO_QeL9AXkwDQYJKoZIhvcNAQELBQADggIBAIfdoJ_4IIkF0S1Bzgmk6dR6XAYbDsPGcEyiQccGCvMnEOf0EVwXDEYvGsVXsR9h6FA04P7vg5Lx9lGBmI1_0QMYBiIeHT4Kyl8FZ3bTMIiOUJ0MFzKHCrc8snrkkL-iDcJP0AriS-SzgMj7TVFjE2_1LwnHWFo7WWBTnmEEivU_-nbVkqelwISE-MH9wgWscmovmIkZ9534teeL1K6rbg4eenjgyu_iHs4PZ6W7nJZ918Vv5EYbZNhREUgZgaKOyKLT3fDRkwE58FL7der8Osd5ltmus2RjjnmAkJnl5Xzc2u30n39QXRVkeX-HCdIBQL9ve03-XRmUL2Q9w3MkPTiXid0UEPYp19DYcZNfunJtYtnvIfYEze6LY6mJpxo7N3s4T3WsdgHa5nJDuN2DbnIX0zxAj00cz-K0KN0G8Bi3hAJPx1fqCZmIgZHYX9hdkCzJu0nXqmdSY4NVtbzSU9vPL49RBhfv2il4P27owGivOv2DTwSWlvUXcOBJ3xVIuWxHZA-WUqXgBwkMwg59kc5AY7Nq0xXuKkRVFrQvkWeMBakce9I1yyMPgK6XnraY7cyUjakLKj5RL6cjMbldmY567gNv8rD90Q86jbO0fCVTSoontEQGxu3reN1C2XAu6IsfCSmLCesA5l_Bssu71jPi0vV4mVB9-7BL8CiWzPscaGF1dGhEYXRhWKVJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY8EAAABYnoXR4UpRQ5S2w3bKTb1-LAAgXsHlGa0A3EdEbxHSQNVKIxHRxYZ8O-INNzeeANMAY8ulAQIDJiABIVggWpjzKg_c8UBNYBBiZqeDrTITBipKHOJv5KJIPuVQm2YiWCB0p58-0ZxWskcZMiPn2w7PgifbLhGbSAK4l9B4SJNQDKA\",\"transports\":[]},\"clientExtensionResults\":{}}";


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
