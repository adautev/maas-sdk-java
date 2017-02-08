package com.miracl.maas_sdk;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.function.Consumer;

public class MiraclClientTest {

	MiraclClient client;
	MiraclStatePreserver preserver;
	Properties properties;

	@BeforeClass
	public void setUpClass() throws Exception {
		properties = new Properties();
		try (InputStream in = getClass().getClassLoader().getResourceAsStream("test.properties")) {
			properties.load(in);
		}
	}

	@BeforeMethod
	public void setUp() throws Exception {
		client = new MiraclClientNoNetworkMock("MOCK_CLIENT", "MOCK_SECRET", "MOCK_URL");
		preserver = new MiraclMapStatePreserver(new HashMap<>());
	}

	@AfterMethod
	public void tearDown() throws Exception {
		client = null;
		preserver = null;
	}

	@Test
	public void testGetAuthorizationRequestUrl() throws Exception {
		final String authorizationRequestUrl = client.getAuthorizationRequestUrl(preserver).toASCIIString();
		final String miracl_state = preserver.get("miracl_state");
		Assert.assertNotNull(miracl_state);
		final String miracl_nonce = preserver.get("miracl_nonce");
		Assert.assertNotNull(miracl_nonce);
		Assert.assertTrue(authorizationRequestUrl.contains("state=" + miracl_state));
		Assert.assertTrue(authorizationRequestUrl.contains("nonce=" + miracl_nonce));
	}

	@Test
	public void testClearUserInfo() throws Exception {
		preserver.put("miracl_userinfo", "data");
		client.clearUserInfo(preserver);
		Assert.assertNull(preserver.get("miracl_userinfo"));
	}

	@Test
	public void testClearUserInfoAndSession() throws Exception {
		preserver.put("miracl_userinfo", "data");
		preserver.put("miracl_token", "data");
		client.clearUserInfoAndSession(preserver);
		Assert.assertNull(preserver.get("miracl_userinfo"));
		Assert.assertNull(preserver.get("miracl_token"));
	}

	@Test
	public void testIsAuthorized() throws Exception {
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
	public void testGetEmailAndUserID() throws Exception {
		preserver.put("miracl_token", "MOCK_TOKEN");
		String email = "a@b.c";
		String sub = "123";
		preserver.put("miracl_userinfo", "{\"email\":\"" + email + "\",\"sub\":\"" + sub + "\"}");

		Assert.assertEquals(client.getEmail(preserver), email);
		Assert.assertEquals(client.getUserId(preserver), sub);
	}

	@Test
	public void testAuthFlow() throws Exception {
		client.getAuthorizationRequestUrl(preserver);
		final String miracl_state = preserver.get("miracl_state");
		final String miracl_nonce = preserver.get("miracl_nonce");

		String queryString = "state=" + miracl_state + "&nonce=" + miracl_nonce + "&code=MOCK_CODE";
		String tokenInput = "MOCK_TOKEN";

		String token = client.validateAuthorization(preserver, queryString);
		Assert.assertEquals(tokenInput, token);
		final String id = client.getUserId(preserver);
		Assert.assertEquals(id, "MOCK_USER");

	}

	@Test
	public static void testUseProxy() throws Exception {
		MiraclClient.useProxy("localhost", "8888");

		Assert.assertEquals(System.getProperty("http.proxyHost"), "localhost");
		Assert.assertEquals(System.getProperty("https.proxyHost"), "localhost");
		Assert.assertEquals(System.getProperty("http.proxyPort"), "8888");
		Assert.assertEquals(System.getProperty("https.proxyPort"), "8888");
	}

	@Test
	public void testValidateNonJsonToken() throws Exception {
		try {
			client = new MiraclClient("clientId", "clientSecret", "bad URL");
			client.validateToken("RS256", "");
		} catch (MiraclSystemException expected) {
			return;
		}

		Assert.fail("Token validation did not fail with non-JSON token");
	}

	@Test
	public void testBuildJwtProcessorBadUrl() throws Exception {
		try {
			client = new MiraclClient("clientId", "clientSecret", "bad URL");
			client.buildJwtProcessor(JWSAlgorithm.HS256, "bad URL");
		} catch (MiraclException e) {
			Assert.assertTrue(e.getMessage().contains("bad URL"));
			return;
		}

		Assert.fail("It was possible to build a JWT processor with an invalid URL");
	}

	@Test
	public void testBuildMiraclClientBadRedirectUrl() throws Exception {
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
	public void testExtractClaims() throws Exception {
		JWTClaimsSet claims = client.extractClaims("", JWSAlgorithm.HS256, properties.getProperty("jwt.valid"));
		Assert.assertEquals(claims.getSubject(), "test@miracl.com");
	}

	@Test
	public void testValidateToken() throws Exception {
		// Validation should pass for this one
		try {
			client.validateToken(JWSAlgorithm.HS256, properties.getProperty("jwt.valid"));
		} catch (MiraclSystemException e) {
			Assert.fail("JWT signature validation failed for a valid signature");
		}

		// Validation should pass for this one
		try {
			client.validateToken("HS256", properties.getProperty("jwt.valid"));
		} catch (MiraclSystemException e) {
			Assert.fail("JWT signature validation failed for a valid signature");
		}

		// Validation should fail for this one
		try {
			client.validateToken(JWSAlgorithm.HS256, properties.getProperty("jwt.invalidSignature"));
		} catch (MiraclSystemException e) {
			Assert.assertTrue(e.getMessage().contains("Invalid signature"));
			return;
		}
		
		Assert.fail("JWT signature validation succeeded for an invalid signature");
	}
	
	@Test
	public void testGetJWSAlgorithm() throws Exception {
		Assert.assertEquals(client.getJWSAlgorithm("HS256"), JWSAlgorithm.HS256);
	}
	
	@Test
	public void testRequestUserInfo() throws Exception {
		UserInfo info = client.requestUserInfo("token");
		Assert.assertEquals(info.getClaim("Email"), "test2@example.com");
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

	protected void createFile(String filename, List<String> lines, Consumer<URL> consumer) throws Exception {
		Path file = Paths.get(filename);
		Files.write(file, lines, Charset.forName("UTF-8"));
		URL url = file.toUri().toURL();

		consumer.accept(url);

		Files.delete(file.toAbsolutePath());
	}
}
