package com.miracl.maas_sdk;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import net.minidev.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.testng.reporters.Files;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Date;

public class PushJWTClaimsVerifierTest {

    @Test(expectedExceptions = BadJWTException.class, expectedExceptionsMessageRegExp = "Missing token expiration claim")
    public void testVerify_noExpirationClaim() throws BadJWTException {
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .build();
        verifier.verify(claimsSet);
    }

    @Test(expectedExceptions = MiraclSystemException.class, expectedExceptionsMessageRegExp = ".+?events.+")
    public void testVerify_noEvents() throws BadJWTException {
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .build();
        verifier.verify(claimsSet);
    }

    @Test(expectedExceptions = MiraclSystemException.class, expectedExceptionsMessageRegExp = ".+?newUser.+")
    public void testVerify_noNewUser() throws BadJWTException {
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .claim("events", new JSONObject())
                .build();
        verifier.verify(claimsSet);
    }

    @Test(expectedExceptions = MiraclSystemException.class, expectedExceptionsMessageRegExp = ".+?" + IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH + ".+")
    public void testVerify_noMPinHash() throws BadJWTException {
        JSONObject events = new JSONObject();
        JSONObject newUser = new JSONObject();
        events.put("newUser", newUser);
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .claim("events", events)
                .build();
        verifier.verify(claimsSet);
    }
    @Test(expectedExceptions = MiraclSystemException.class, expectedExceptionsMessageRegExp = ".+?" + IdentityActivationModel.ACTIVATION_KEY + ".+")
    public void testVerify_noActivationKey() throws BadJWTException {
        JSONObject events = new JSONObject();
        JSONObject newUser = new JSONObject();
        newUser.put(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH, "1234");
        events.put("newUser", newUser);
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .claim("events", events)
                .build();
        verifier.verify(claimsSet);
    }
    @Test(expectedExceptions = BadJWTException.class, expectedExceptionsMessageRegExp = ".+?issuer.+")
    public void testVerify_invalidIssuer() throws BadJWTException {
        JSONObject events = new JSONObject();
        JSONObject newUser = new JSONObject();
        newUser.put(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH, "1234");
        newUser.put(IdentityActivationModel.ACTIVATION_KEY, "1234");
        events.put("newUser", newUser);
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer("issuer")
                .expirationTime(new Date(new Date().getTime() + 10000))
                .claim("events", events)
                .build();
        verifier.verify(claimsSet);
    }

    @Test
    public void testVerify_valid_nullSecurityContext() throws BadJWTException {
        JSONObject events = new JSONObject();
        JSONObject newUser = new JSONObject();
        newUser.put(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH, "1234");
        newUser.put(IdentityActivationModel.ACTIVATION_KEY, "1234");
        events.put("newUser", newUser);
        PushJWTClaimsVerifier verifier = new PushJWTClaimsVerifier();
        JWTClaimsSet claimsSet =new JWTClaimsSet.Builder()
                .subject("mr.crowley@example.com")
                .issuer(MiraclConfig.ISSUER)
                .expirationTime(new Date(new Date().getTime() + 10000))
                .claim("events", events)
                .build();
        verifier.verify(claimsSet, null);
    }

}