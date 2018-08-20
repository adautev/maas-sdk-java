package com.miracl.maas_sdk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import net.minidev.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.testng.reporters.Files;

import javax.crypto.spec.SecretKeySpec;

public class JwtValidatorTest {

    public static final String SAMPLE_JWS_KID = "1234";
    Properties properties;
    JwtValidator validator;

    @BeforeClass
    public void setUpClass() throws Exception {
        properties = new Properties();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("test.properties")) {
            properties.load(in);
        }
    }

    @Test
    public void testValidatePushToken_invalidToken() {
        validator = new JwtValidator("RS256");
        Assert.assertFalse(validator.validateToken(""));
    }

    @Test
    public void testValidatePushToken_validToken() {
        ConfigurableJWTProcessor<SecurityContext> processor;
        JWKSource<SecurityContext> keySource;
        JWKSet keySet;
        JWSKeySelector<SecurityContext> keySelector;

        File file = new File(getClass().getClassLoader().getResource("jwk.json").getFile());

        try {
            JsonObject jwkFileContent = Json.parse(IOUtils.readFileToString(file, Charset.forName("UTF-8"))).asObject();
            processor = new DefaultJWTProcessor<>();
            keySet = JWKSet.load(file);
            keySource = new ImmutableJWKSet<>(keySet);
            keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, keySource);
            processor.setJWSKeySelector(keySelector);


            RSAPrivateKey privateKey = null;
            validator = new JwtValidator("HS256", keySource);
            String validJWT = generateValidSignedJWT(JWSAlgorithm.HS256, jwkFileContent.get("keys").asArray().get(0).asObject().get("k").asString());
            Assert.assertTrue(validator.validatePushToken(validJWT));
        } catch (IOException | java.text.ParseException e) {
            Assert.fail();
        }
    }

    @Test
    public void testBuildJwtProcessor_BadUrl() {
        try {
            validator = new JwtValidator(JWSAlgorithm.HS256, "bad URL");
            validator.buildJwtProcessor(JWSAlgorithm.RS256);
        } catch (MiraclClientException e) {
            Assert.assertTrue(e.getMessage().contains("bad URL"));
            return;
        }

        Assert.fail("It was possible to build a JWT processor with an invalid URL");
    }

    @Test
    public void testBuildJwtProcessor() throws Exception {
        URL url = createMockHttpUrl("jwk.json");

        ConfigurableJWTProcessor<SecurityContext> processor;
        validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256, url);
        processor = validator.buildJwtProcessor(JWSAlgorithm.HS256);

        try {
            JWTClaimsSet claims = processor.process(properties.getProperty("jwt.valid"), null);
            Assert.assertEquals(claims.getClaim("Email"), "test2@miracl.com");
        } catch (ParseException | BadJOSEException | JOSEException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testExtractClaims() throws Exception {
        validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256);
        JWTClaimsSet claims = validator.extractClaims(properties.getProperty("jwt.valid"));
        Assert.assertEquals(claims.getSubject(), "test@miracl.com");
    }

    @Test
    public void testValidateToken() {
        // Validation should pass for this one
        try {
            validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256);
            validator.validateToken(properties.getProperty("jwt.valid"));
        } catch (MiraclSystemException e) {
            Assert.fail("JWT signature validation failed for a valid signature #1: " + e.getMessage());
        }

        // Validation should pass for this one
        try {
            validator = new JwtValidatorNoNetworkMock("HS256");
            validator.validateToken(properties.getProperty("jwt.valid"));
        } catch (MiraclSystemException e) {
            Assert.fail("JWT signature validation failed for a valid signature #2: " + e.getMessage());
        }

        // Validation should fail for this one
        try {
            validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256);
            Assert.assertFalse(validator.validateToken(properties.getProperty("jwt.invalidSignature")));
        } catch (MiraclSystemException e) {
            Assert.assertTrue(e.getMessage().contains("Invalid signature"));
            return;
        }

    }

    @Test
    public void testGetJWSAlgorithm() {
        Assert.assertEquals(JwtValidator.getJWSAlgorithm("HS256"), JWSAlgorithm.HS256);
    }

    /**
     * Create a mock HTTP URL for testing functionality that requires such.
     *
     * @param filename A filename, stored in test/resources, to use for source
     * @return
     * @throws Exception
     */
    protected URL createMockHttpUrl(String filename) throws Exception {
        URLConnection mockConnection = new MockURLConnection(filename);
        URLStreamHandler handler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(final URL arg0) throws IOException {
                return mockConnection;
            }
        };
        return new URL("http", "example.com", 80, "", handler);
    }

    private String generateValidSignedJWT(JWSAlgorithm algorithm, String key) {
        KeyPairGenerator keyGenerator = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Assert.fail("Unable to generate RSA Key");
        }
        byte[] decodedKey = Base64.getDecoder().decode(key);
        keyGenerator.initialize(1024);

        try {
            JWSSigner signer = new MACSigner(new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"));
            String currentDate = Long.toString(new Date(new Date().getTime()).getTime());
            String futureDate = Long.toString(new Date(new Date().getTime() + 100000).getTime());
            URI payloadTemplateUri = getClass().getClassLoader().getResource("pluggableVerificationPushJWTPayload.json").toURI();
            String payloadTemplate = Files.readFile(new File(payloadTemplateUri));
            String payload = String.format(payloadTemplate, MiraclConfig.ISSUER, currentDate, futureDate, futureDate);
            JWSObject jwsObject = new JWSObject(
                    new JWSHeader.Builder(algorithm).keyID(SAMPLE_JWS_KID).build(),
                    new Payload(payload));
            jwsObject.sign(signer);
            return jwsObject.serialize();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        Assert.fail("Unable to sign dummy JWT.");
        return "";
    }
}
