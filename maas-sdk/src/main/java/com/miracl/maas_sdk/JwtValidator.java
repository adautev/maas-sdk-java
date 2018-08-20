package com.miracl.maas_sdk;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import net.minidev.json.JSONObject;

/**
 * Tools related to JWT signature validation and working with claims.
 */
public class JwtValidator {

    private static final String KEY_SOURCE_URL = MiraclConfig.ISSUER + MiraclConfig.CERTS_API_ENDPOINT;
    private JWSAlgorithm algorithm;
    private JWKSource<SecurityContext> jwkSource;
    private URL keySourceUrl;

    public JwtValidator(JWSAlgorithm algorithm, URL keySourceUrl) {
        this.algorithm = algorithm;
        this.keySourceUrl = keySourceUrl;
    }

    public JwtValidator(String algorithm, JWKSource<SecurityContext> jwkSource) {
        this.algorithm = JWSAlgorithm.parse(algorithm);
        this.jwkSource = jwkSource;
    }

    public JwtValidator(JWSAlgorithm algorithm, String keySourceUrl) {
        this.algorithm = algorithm;

        try {
            this.keySourceUrl = new URL(keySourceUrl);
        } catch (MalformedURLException e) {
            throw new MiraclClientException(e);
        }
    }

    public JwtValidator(JWSAlgorithm algorithm) {
        this(algorithm, KEY_SOURCE_URL);
    }

    public JwtValidator(String algorithm) {
        this(getJWSAlgorithm(algorithm));
    }

    /**
     * Create a JWT processor that can be used to verify tokens and extract
     * claims.
     *
     * @return A DefaultJWTProcessor
     * @throws MiraclClientException When the remote JWK URL is not valid
     */
    ConfigurableJWTProcessor<SecurityContext> buildJwtProcessor(JWSAlgorithm algorithm) {
        ConfigurableJWTProcessor<SecurityContext> processor;
        JWKSource<SecurityContext> keySource;
        JWSKeySelector<SecurityContext> keySelector;

        processor = new DefaultJWTProcessor<>();
        keySource = new RemoteJWKSet<>(keySourceUrl);
        keySelector = new JWSVerificationKeySelector<>(algorithm, keySource);
        processor.setJWSKeySelector(keySelector);
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<SecurityContext>() {
            @Override
            public void verify(JWTClaimsSet claimsSet) throws BadJWTException {
                super.verify(claimsSet);
                Date expirationTime = claimsSet.getExpirationTime();
                if (expirationTime == null) {
                    throw new BadJWTException("Missing token expiration claim");
                }

                if (!MiraclConfig.ISSUER.equals(claimsSet.getIssuer())) {
                    throw new BadJWTException("Token issuer not accepted");
                }
            }
        });

        return processor;
    }

    /**
     * Extracts and returns a JWT's claims.
     *
     * @param token JSON Web Token to validate
     * @return The JWT's claims
     * @throws MiraclClientException When the remote JWK URL is not valid
     * @throws MiraclSystemException When the token could not be validated
     */
    public JWTClaimsSet extractClaims(String token) throws ParseException, JOSEException, BadJOSEException {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = buildJwtProcessor(algorithm);
        return jwtProcessor.process(token, null);
    }

    /**
     * Attempts to validate a JWT, throwing a MiraclSystemException if it
     * cannot.
     *
     * @param token JSON Web Token to validate
     * @throws MiraclClientException When the remote JWK URL is not valid
     * @throws MiraclSystemException When the token could not be validated
     */
    public boolean validateToken(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Get a JWSAlgorithm by its name.
     *
     * @param name
     * @return
     */
    public static JWSAlgorithm getJWSAlgorithm(String name) {
        return new JWSAlgorithm(name);
    }

    public boolean validatePushToken(String newUserToken) {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = buildPushJwtProcessor();
            jwtProcessor.process(newUserToken, null);
            return true;
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (BadJOSEException e) {
            e.printStackTrace();
        }
        return false;
    }

    private ConfigurableJWTProcessor<SecurityContext> buildPushJwtProcessor() {
        ConfigurableJWTProcessor<SecurityContext> processor;
        JWKSource<SecurityContext> keySource;
        JWSKeySelector<SecurityContext> keySelector;
        processor = new DefaultJWTProcessor<>();
        if(jwkSource == null) {
            keySource = new RemoteJWKSet<>(keySourceUrl);
        } else {
            keySource = jwkSource;
        }
        keySelector = new JWSVerificationKeySelector<>(algorithm, keySource);
        processor.setJWSKeySelector(keySelector);
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<SecurityContext>() {

            private void verifyClaims(JWTClaimsSet claimsSet) throws BadJWTException {
                Date expirationTime = claimsSet.getExpirationTime();
                if (expirationTime == null) {
                    throw new BadJWTException("Missing token expiration claim");
                }

                JSONObject eventsClaim = (JSONObject) claimsSet.getClaim("events");

                if (eventsClaim == null) {
                    throw new MiraclSystemException("\"events\" key not found in activation JWT");
                }
                Object newUser = eventsClaim.get("newUser");
                if (newUser == null) {
                    throw new MiraclSystemException("\"newUser\" key not found in activation JWT");
                }
                String mpinIdHash = ((JSONObject) newUser).getAsString(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH);
                if (mpinIdHash == null || mpinIdHash.equals("")) {
                    throw new MiraclSystemException(String.format("\"%s\" key not found in activation JWT", IdentityActivationModel.MPIN_ID_HASH_KEY));
                }
                String activationKey = ((JSONObject) newUser).getAsString(IdentityActivationModel.ACTIVATION_KEY);
                if (activationKey == null || activationKey.equals("")) {
                    throw new MiraclSystemException(String.format("\"%s\" key not found in activation JWT", IdentityActivationModel.ACTIVATION_KEY));
                }
                if (!MiraclConfig.ISSUER.equals(claimsSet.getIssuer())) {
                    throw new BadJWTException("Token issuer not accepted");
                }
            }

            @Override
            public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
                super.verify(claimsSet, context);
                verifyClaims(claimsSet);
            }

            @Override
            public void verify(JWTClaimsSet claimsSet) throws BadJWTException {
                super.verify(claimsSet);
                verifyClaims(claimsSet);
            }
        });

        return processor;
    }
}
