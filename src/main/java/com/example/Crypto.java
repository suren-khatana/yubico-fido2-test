package com.example;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

final class Crypto {
    // Values from
    // https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/mathematical-routines-for-the-nist-prime-elliptic-curves.cfm
    // cross-referenced with "secp256r1" in https://www.secg.org/sec2-v2.pdf
    private static final EllipticCurve P256 =
            new EllipticCurve(
                    new ECFieldFp(
                            new BigInteger(
                                    "115792089210356248762697446949407573530086143415290314195533631308867097853951",
                                    10)),
                    new BigInteger(
                            "115792089210356248762697446949407573530086143415290314195533631308867097853948", 10),
                    new BigInteger(
                            "41058363725152142129326129780047268409114441015993725554835256314039467401291", 10));

    static boolean isP256(ECParameterSpec params) {
        return P256.equals(params.getCurve());
    }

    public static boolean verifySignature(
            X509Certificate attestationCertificate,
            ByteArray signedBytes,
            ByteArray signature,
            COSEAlgorithmIdentifier alg) {
        return verifySignature(attestationCertificate.getPublicKey(), signedBytes, signature, alg);
    }

    public static boolean verifySignature(
            PublicKey publicKey,
            ByteArray signedBytes,
            ByteArray signatureBytes,
            COSEAlgorithmIdentifier alg) {
        try {
            Signature signature = Signature.getInstance(WebAuthnCodecs.getJavaAlgorithmName(alg));
            signature.initVerify(publicKey);
            signature.update(signedBytes.getBytes());
            return signature.verify(signatureBytes.getBytes());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new RuntimeException(
                    String.format(
                            "Failed to verify signature. This could be a problem with your JVM environment, or a bug in webauthn-server-core. Public key: %s, signed data: %s , signature: %s",
                            publicKey, signedBytes.getBase64Url(), signatureBytes.getBase64Url()),
                    e);
        }
    }
    
    public static ByteArray sha1(ByteArray bytes) throws NoSuchAlgorithmException {
        return new ByteArray(MessageDigest.getInstance("SHA-1").digest(bytes.getBytes()));
    }
}
