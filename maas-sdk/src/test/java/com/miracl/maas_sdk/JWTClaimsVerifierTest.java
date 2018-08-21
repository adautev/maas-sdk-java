package com.miracl.maas_sdk;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import org.testng.annotations.Test;

import java.util.Date;

public class JWTClaimsVerifierTest {

    @Test(expectedExceptions = BadJWTException.class, expectedExceptionsMessageRegExp = "Missing token expiration claim")
    public void testVerify_noExpirationClaim() throws BadJWTException {
        JWTClaimsVerifier verifier = new JWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .build();
        verifier.verify(claimsSet);
    }

    @Test(expectedExceptions = BadJWTException.class, expectedExceptionsMessageRegExp = ".+?issuer.+")
    public void testVerify_invalidIssuer() throws BadJWTException {

        JWTClaimsVerifier verifier = new JWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer("issuer")
                .expirationTime(new Date(new Date().getTime() + 10000))
                .build();
        verifier.verify(claimsSet);
    }

    @Test
    public void testVerify_valid_nullSecurityContext() throws BadJWTException {
        JWTClaimsVerifier verifier = new JWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .build();
        verifier.verify(claimsSet, null);
    }

    @Test
    public void testVerify_valid_noSecurityContext() throws BadJWTException {
        JWTClaimsVerifier verifier = new JWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .build();
        verifier.verify(claimsSet);
    }

}