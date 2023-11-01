package se.digg.sdg.samples.directaccessclient.components;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import se.swedenconnect.security.credential.PkiCredential;

public class JWKFactory {
    public static JWK create(PkiCredential credentials) throws JOSEException {
        final JWK key;
        if ("RSA".equals(credentials.getCertificate().getPublicKey().getAlgorithm())) {
            key = new RSAKey.Builder(RSAKey.parse(credentials.getCertificate()))
                    .privateKey(credentials.getPrivateKey())
                    .algorithm(new Algorithm("RS256"))
                    .keyIDFromThumbprint()
                    .build();
        } else if ("EC".equals(credentials.getCertificate().getPublicKey().getAlgorithm())) {
            key = new ECKey.Builder(ECKey.parse(credentials.getCertificate()))
                    .privateKey(credentials.getPrivateKey())
                    .algorithm(new Algorithm("ES256"))
                    .keyIDFromThumbprint()
                    .build();
        } else {
            throw new SecurityException(
                    "Unsupported key type - " + credentials.getCertificate().getPublicKey().getAlgorithm());
        }
        return key;
    }
}
