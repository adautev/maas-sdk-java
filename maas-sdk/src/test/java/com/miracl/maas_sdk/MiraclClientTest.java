package com.miracl.maas_sdk;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.HashMap;

public class MiraclClientTest {

	MiraclClient client;
	MiraclStatePreserver preserver;

	@BeforeClass
	public void setUpClass() throws Exception {
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
	public void testParseAuthenticationResponse() throws Exception {
		try {
			client.parseAuthenticationResponse("");
		} catch (MiraclException e) {
			Assert.fail();
		}
	}
}
