package com.miracl.maas_sdk;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xebialabs.restito.server.StubServer;
import org.glassfish.grizzly.http.util.HttpStatus;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.function.Consumer;

import static com.xebialabs.restito.builder.stub.StubHttp.whenHttp;
import static com.xebialabs.restito.semantics.Action.*;
import static com.xebialabs.restito.semantics.Condition.endsWithUri;

public class MiraclClientTest {

    public static final String SAMPLE_JWS_KID = "1234";
    private static final String TEST_URL = "http://example.com";

    MiraclClient client;
    MiraclStatePreserver preserver;
    Properties properties;
    private StubServer server;

    @BeforeClass
    public void setUpClass() throws Exception {
        properties = new Properties();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("test.properties")) {
            properties.load(in);
        }
    }

    @BeforeMethod
    public void setUp() {
        client = new MiraclClientNoNetworkMock("MOCK_CLIENT", "MOCK_SECRET", "MOCK_URL");
        preserver = new MiraclMapStatePreserver(new HashMap<>());
        server = new StubServer().run();
        MiraclConfig.setIssuer(MiraclConfig.DEFAULT_ISSUER);
    }

    @AfterMethod
    public void tearDown() {
        client = null;
        preserver = null;
        server.stop();
    }

    @Test
    public void testGetAuthorizationRequestUrl() {
        final String authorizationRequestUrl = client.getAuthorizationRequestUrl(preserver).toASCIIString();
        final String miracl_state = preserver.get("miracl_state");
        Assert.assertNotNull(miracl_state);
        final String miracl_nonce = preserver.get("miracl_nonce");
        Assert.assertNotNull(miracl_nonce);
        Assert.assertTrue(authorizationRequestUrl.contains("state=" + miracl_state));
        Assert.assertTrue(authorizationRequestUrl.contains("nonce=" + miracl_nonce));
    }

    @Test
    public void testClearUserInfo() {
        preserver.put("miracl_userinfo", "data");
        client.clearUserInfo(preserver);
        Assert.assertNull(preserver.get("miracl_userinfo"));
    }

    @Test
    public void testClearUserInfoAndSession() {
        preserver.put("miracl_userinfo", "data");
        preserver.put("miracl_token", "data");
        client.clearUserInfoAndSession(preserver);
        Assert.assertNull(preserver.get("miracl_userinfo"));
        Assert.assertNull(preserver.get("miracl_token"));
    }

    @Test
    public void testIsAuthorized() {
        Assert.assertFalse(client.isAuthorized(preserver));

        preserver.put("miracl_token", "MOCK_TOKEN");
        String email = "a@b.c";
        String sub = "123";
        preserver.put("miracl_userinfo", "{\"email\":\"" + email + "\",\"sub\":\"" + sub + "\"}");
        Assert.assertTrue(client.isAuthorized(preserver));

        client.clearUserInfoAndSession(preserver);
        Assert.assertFalse(client.isAuthorized(preserver));

    }

    @Test
    public void testGetEmailAndUserID() {
        preserver.put("miracl_token", "MOCK_TOKEN");
        String email = "a@b.c";
        String sub = "123";
        preserver.put("miracl_userinfo", "{\"email\":\"" + email + "\",\"sub\":\"" + sub + "\"}");

        Assert.assertEquals(client.getEmail(preserver), email);
        Assert.assertEquals(client.getUserId(preserver), sub);
    }

    @Test
    public void testAuthFlow() {
        client.getAuthorizationRequestUrl(preserver);

        final String miracl_state = preserver.get("miracl_state");
        final String miracl_nonce = preserver.get("miracl_nonce");

        String queryString = "state=" + miracl_state + "&nonce=" + miracl_nonce + "&code=MOCK_CODE";
        String tokenInput = "MOCK_TOKEN";
        String token = client.validateAuthorization(preserver, queryString);

        Assert.assertEquals(tokenInput, token);
        Assert.assertEquals(client.getUserId(preserver), "MOCK_USER");
    }

    @Test
    public void testVerifyAuthenticationSuccess() throws Exception {
        AuthenticationResponse success = new AuthenticationSuccessResponse(new URI(TEST_URL), null, null, null, null, null, null);
        AuthenticationResponse error = new AuthenticationErrorResponse(new URI(TEST_URL), new ErrorObject(""), null, null);

        try {
            client.validateNonErrorResponse(success);
        } catch (MiraclClientException expected) {
            Assert.fail("AuthenticationSuccessResponses are identified as errors");
        }

        try {
            client.validateNonErrorResponse(error);
        } catch (MiraclClientException expected) {
            return;
        }

        Assert.fail("AuthenticationErrorResponses are not detected as such");
    }

    @Test
    public static void testUseProxy() {
        MiraclClient.useProxy("localhost", "8888");

        Assert.assertEquals(System.getProperty("http.proxyHost"), "localhost");
        Assert.assertEquals(System.getProperty("https.proxyHost"), "localhost");
        Assert.assertEquals(System.getProperty("http.proxyPort"), "8888");
        Assert.assertEquals(System.getProperty("https.proxyPort"), "8888");
    }

    @Test
    public void testBuildMiraclClientBadRedirectUrl() {
        try {
            client = new MiraclClient("clientId", "clientSecret", "bad URL");
        } catch (MiraclSystemException e) {
            Assert.assertTrue(e.getMessage().contains("Illegal character"));
            return;
        }

        Assert.fail("It was possible to construct the MiraclClient processor with an invalid redirect URL");
    }

    @Test
    public void testRequestProviderInfo() throws Exception {
        String expected = "{\"test\": \"example\"}";
        List<String> lines = Arrays.asList(expected);

        createFile("test-prov.txt", lines, (url) -> {
            client = new MiraclClient("client", "secret", "http://127.0.0.1");
            String providerInfo = null;

            try {
                providerInfo = client.requestProviderInfo(url).trim();
            } catch (Exception e) {
                Assert.fail(e.getMessage());
            }

            Assert.assertEquals(providerInfo, expected);
        });

    }

    @Test
    public void testBuildAuthenticationUri() throws Exception {
        URI result = client.buildAuthenticationUri("test");
        Assert.assertEquals(result.toString(), "/?test");
    }

    @Test
    public void testRequestUserInfo() throws Exception {
        UserInfo info = client.requestUserInfo("token");
        Assert.assertEquals(info.getClaim("Email"), "test2@example.com");
    }

    @Test
    public void testValidateNonErrorResponse() throws Exception {
        UserInfoResponse success = new UserInfoSuccessResponse(new UserInfo(new Subject()));
        UserInfoResponse error = new UserInfoErrorResponse(new BearerTokenError("", ""));

        try {
            client.validateNonErrorResponse(success);
        } catch (MiraclClientException e) {
            Assert.fail("A UserInfoSuccessResponse was erroneously identified as an error");
        }

        try {
            client.validateNonErrorResponse(error);
        } catch (MiraclClientException e) {
            // An exception is expected because error is a UserInfoErrorResponse
            return;
        }

        Assert.fail("A UserInfoErrorResponse was erroneously identified as a success");
    }

    @Test
    public void testGetJWTSigningAlgorithm_successfulExecution() {
        String jwt = generateDummySignedJWT(JWSAlgorithm.RS256, TEST_URL);
        Assert.assertEquals(JWSAlgorithm.RS256.toString(), client.getJWTSigningAlgorithm(jwt));
        jwt = generateDummySignedJWT(JWSAlgorithm.RS384, null);
        Assert.assertEquals(JWSAlgorithm.RS384.toString(), client.getJWTSigningAlgorithm(jwt));
        jwt = generateDummySignedJWT(JWSAlgorithm.RS512, null);
        Assert.assertEquals(JWSAlgorithm.RS512.toString(), client.getJWTSigningAlgorithm(jwt));
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_UNABLE_TO_PARSE_JWT_HEADER)
    public void testGetJWTSigningAlgorithm_noHeader() {
        client.getJWTSigningAlgorithm("xx.xx.xx");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_SIGNING_ALGORITHM_NOT_SPECIFIED_IN_JWT_HEADER)
    public void testGetJWTSigningAlgorithm_noAlgInHeader() {
        String dummyHeader = Base64.getEncoder().encodeToString("{\"key\" : \"value\"}".getBytes());
        client.getJWTSigningAlgorithm(dummyHeader + ".xx.xx");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_INVALID_JWT)
    public void testGetJWTSigningAlgorithm_should_throw_exception_whenJWTNotSigned() {
        String jwt = generateDummyNotSignedJWT();
        client.getJWTSigningAlgorithm(jwt);
    }

    @Test
    public void testGetClientActivationEndpointURL() {
        Assert.assertEquals(String.format("%s%s", MiraclConfig.ISSUER, MiraclConfig.PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT), new MiraclClient("clientId", "clientSecret", "http://redirect.url").getClientActivationEndpointURL());
    }

    @Test
    public void testSuccessful_IdentityActivation() {
        whenHttp(server)
                .match(endsWithUri(MiraclConfig.PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT))
                .then(status(HttpStatus.OK_200));
        MiraclConfig.setIssuer(String.format("http://localhost:%s", server.getPort()));
        client.activateIdentity(new IdentityActivationModel("dummy", "dummy", "dummy"));
    }

    @Test
    public void testPullVerification_SuccessfulExecution() {
        whenHttp(server)
                .match(endsWithUri(MiraclConfig.PLUGGABLE_VERIFICATION_PULL_ENDPOINT))
                .then(status(HttpStatus.OK_200), header("Content-Type", "application/json"), stringContent(String.format("{\"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"%s\" }",
                        IdentityActivationModel.ACTIVATION_KEY,
                        IdentityActivationModel.MPIN_ID_HASH_KEY,
                        IdentityActivationModel.USER_ID_KEY,
                        IdentityActivationModel.EXPIRATION_TIME,
                        new Date(new Date().getTime() + 100000).getTime())));
        MiraclConfig.setIssuer(String.format("http://localhost:%s", server.getPort()));
        client.pullVerification("dummy");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_PV_PULL_UNABLE_TO_CREATE_POST_REQUEST)
    public void testPullVerification_NoEndpoint() {
        client.pullVerification("dummy");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = ".+?expired.+")
    public void testDateExpired_PluggableVerificationPull() {
        whenHttp(server)
                .match(endsWithUri(MiraclConfig.PLUGGABLE_VERIFICATION_PULL_ENDPOINT))
                .then(status(HttpStatus.OK_200), header("Content-Type", "application/json"), stringContent(String.format("{\"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"%s\" }",
                        IdentityActivationModel.ACTIVATION_KEY,
                        IdentityActivationModel.MPIN_ID_HASH_KEY,
                        IdentityActivationModel.USER_ID_KEY,
                        IdentityActivationModel.EXPIRATION_TIME,
                        new Date(new Date().getTime()).getTime() / 1000)));
        MiraclConfig.setIssuer(String.format("http://localhost:%s", server.getPort()));
        client.pullVerification("dummy");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = ".+?hash.+")
    public void testNoMPinIdHash_PluggableVerificationPull() {
        whenHttp(server)
                .match(endsWithUri(MiraclConfig.PLUGGABLE_VERIFICATION_PULL_ENDPOINT))
                .then(status(HttpStatus.OK_200), header("Content-Type", "application/json"), stringContent(String.format("{\"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"%s\" }",
                        IdentityActivationModel.ACTIVATION_KEY,
                        "",
                        IdentityActivationModel.USER_ID_KEY,
                        IdentityActivationModel.EXPIRATION_TIME,
                        new Date(new Date().getTime() + 100000).getTime())));
        MiraclConfig.setIssuer(String.format("http://localhost:%s", server.getPort()));
        client.pullVerification("dummy");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = "Activation.+?")
    public void testNoActivationKey_PluggableVerificationPull() {
        whenHttp(server)
                .match(endsWithUri(MiraclConfig.PLUGGABLE_VERIFICATION_PULL_ENDPOINT))
                .then(status(HttpStatus.OK_200), header("Content-Type", "application/json"), stringContent(String.format("{\"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"dummy\", \"%s\": \"%s\" }",
                        "someOtherKey",
                        IdentityActivationModel.MPIN_ID_HASH_KEY,
                        IdentityActivationModel.USER_ID_KEY,
                        IdentityActivationModel.EXPIRATION_TIME,
                        new Date(new Date().getTime() + 100000).getTime())));
        MiraclConfig.setIssuer(String.format("http://localhost:%s", server.getPort()));
        client.pullVerification("dummy");
    }

    @Test(expectedExceptions = MiraclClientException.class)
    public void testIdentityActivation_ErroneousResponse() {
        whenHttp(server)
                .match(endsWithUri(MiraclConfig.PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT))
                .then(status(HttpStatus.NOT_FOUND_404));
        client.activateIdentity(new IdentityActivationModel("dummy", "dummy", "dummy"));
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_EXECUTE_ACTIVATION_POST_REQUEST)
    public void testIdentityActivation_noActivationEndpoint() {
        client.activateIdentity(new IdentityActivationModel("dummy", "dummy", "dummy"));
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_CREATE_ACTIVATION_POST_REQUEST)
    public void testIdentityActivation_erroneousActivationURL() {
        ((MiraclClientNoNetworkMock)client).setErroneusGetClientActivationEndpointURL(true);
        client.activateIdentity(new IdentityActivationModel("dummy", "dummy", "dummy"));
    }

    @Test
    public void testParseAuthenticationResponseInvalid() throws Exception {
        String expected = "BAD CONTENT";
        List<String> lines = Arrays.asList(expected);
        createFile("test-auth.txt", lines, (url) -> {
            try {
                client.parseAuthenticationResponse(url.toURI());
            } catch (URISyntaxException e) {
                Assert.fail(e.getMessage());
            } catch (MiraclClientException me) {
                Assert.assertTrue(me.getMessage().contains("Missing authorization response parameters"));
                return;
            }

            Assert.fail("It was possible to parse an invalid authentication response");
        });
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_INVALID_JWT)
    public void testgetIdentityActivationModelForRequest_noSigningAlgorithm() throws Exception {
        String jwt = generateDummyNotSignedJWT();
        String newUserToken = String.format("{\"new_user_token\" : \"%s\"}", jwt);
        client.getIdentityActivationModelForRequest(newUserToken);
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_JSON_OBJECT_FROM_REQUEST_BODY)
    public void testgetIdentityActivationModelForRequest_noValidRequest() throws Exception {
        client.getIdentityActivationModelForRequest("dummy");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY)
    public void testgetIdentityActivationModelForRequest_noNewUserToken() throws Exception {
        client.getIdentityActivationModelForRequest("{\"key\": \"value\"}");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY)
    public void testgetIdentityActivationModelForRequest_emptyUserToken() throws Exception {
        client.getIdentityActivationModelForRequest("{\"new_user_token\": \"\"}");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_INVALID_JWT)
    public void testgetIdentityActivationModelForRequest_invalidUserToken() throws Exception {
        client.getIdentityActivationModelForRequest("{\"new_user_token\": \"dummy\"}");
    }

    @Test
    public void testGetEmail_userInfoNotParsable() {
        preserver.put("miracl_userinfo","{{");
        preserver.put("miracl_token","dummy");
        Assert.assertEquals(client.getEmail(preserver),"");
    }

    @Test(expectedExceptions = MiraclClientException.class, expectedExceptionsMessageRegExp = MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_INVALID_JWT)
    public void testgetIdentityActivationModelForRequest_successful() throws Exception {
        client.getIdentityActivationModelForRequest("{\"new_user_token\": \"dummy\"}");
    }

    private void createFile(String filename, List<String> lines, Consumer<URL> consumer) throws Exception {
        Path file = Paths.get(filename);
        Files.write(file, lines, Charset.forName("UTF-8"));
        URL url = file.toUri().toURL();

        consumer.accept(url);

        Files.delete(file.toAbsolutePath());
    }

    private String generateDummyNotSignedJWT() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test@acme.com")
                .issueTime(new Date())
                .build();
        PlainJWT jwt = new PlainJWT(claims);
        return jwt.serialize();
    }

    private String generateDummySignedJWT(JWSAlgorithm algorithm, String payload) {
        KeyPairGenerator keyGenerator = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Assert.fail("Unable to generate RSA Key");
        }
        keyGenerator.initialize(1024);

        KeyPair kp = keyGenerator.genKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        JWSSigner signer = new RSASSASigner(privateKey);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(algorithm).keyID("123").build(),
                new Payload(payload == null ? "In RSA we trust!" : payload));

        try {
            jwsObject.sign(signer);
        } catch (JOSEException e) {
            Assert.fail("Unable to sign dummy JWT.");
            e.printStackTrace();
        }
        return jwsObject.serialize();
    }

    private String generateValidSignedJWT(JWSAlgorithm algorithm, String key) {

        byte[] decodedKey = Base64.getDecoder().decode(key);
        try {
            JWSSigner signer = new MACSigner(new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"));
            String currentDate = Long.toString(new Date(new Date().getTime()).getTime());
            String futureDate = Long.toString(new Date(new Date().getTime() + 100000).getTime());
            URI payloadTemplateUri = getClass().getClassLoader().getResource("pluggableVerificationPushJWTPayload.json").toURI();
            String payloadTemplate = org.testng.reporters.Files.readFile(new File(payloadTemplateUri));
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
