package com.miracl.maas_sdk;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

public class MiraclClientTest
{

	MiraclClient client;
	MiraclStatePreserver preserver;

	@BeforeClass
	public void setUpClass() throws Exception
	{
		//TODO: Remove when not needed - temporary workaround
		trustAllCertificatesOld();
		trustAllCertificatesNew();
	}


	@BeforeMethod
	public void setUp() throws Exception
	{
		client = new MiraclClient("MOCK_CLIENT", "MOCK_SECRET", "MOCK_URL");
		preserver = new MiraclMapStatePreserver(new HashMap<>());
	}

	@AfterMethod
	public void tearDown() throws Exception
	{
		client = null;
		preserver = null;
	}

	@Test
	public void testGetAuthorizationRequestUrl() throws Exception
	{
		final String authorizationRequestUrl = client.getAuthorizationRequestUrl(preserver).toASCIIString();
		final String miracl_state = preserver.get("miracl_state");
		Assert.assertNotNull(miracl_state);
		final String miracl_nonce = preserver.get("miracl_nonce");
		Assert.assertNotNull(miracl_nonce);
		Assert.assertTrue(authorizationRequestUrl.contains("state=" + miracl_state));
		Assert.assertTrue(authorizationRequestUrl.contains("nonce=" + miracl_nonce));
	}

	@Test
	public void testClearUserInfo() throws Exception
	{
		preserver.put("miracl_userinfo", "data");
		client.clearUserInfo(preserver);
		Assert.assertNull(preserver.get("miracl_userinfo"));
	}

	@Test
	public void testClearUserInfoAndSession() throws Exception
	{
		preserver.put("miracl_userinfo", "data");
		preserver.put("miracl_token", "data");
		client.clearUserInfoAndSession(preserver);
		Assert.assertNull(preserver.get("miracl_userinfo"));
		Assert.assertNull(preserver.get("miracl_token"));

	}

	@Test
	public void testIsAuthorized() throws Exception
	{
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
	public void testGetEmailAndUserID() throws Exception
	{
		preserver.put("miracl_token", "MOCK_TOKEN");
		String email = "a@b.c";
		String sub = "123";
		preserver.put("miracl_userinfo", "{\"email\":\"" + email + "\",\"sub\":\"" + sub + "\"}");

		Assert.assertEquals(client.getEmail(preserver), email);
		Assert.assertEquals(client.getUserId(preserver), sub);
	}

	//TODO: Remove when not needed - temporary workaround
	private static void trustAllCertificatesNew()
	{
		javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
				new javax.net.ssl.X509TrustManager()
				{
					public java.security.cert.X509Certificate[] getAcceptedIssuers()
					{
						return new X509Certificate[0];
					}

					public void checkClientTrusted(
							java.security.cert.X509Certificate[] certs, String authType)
					{
					}

					public void checkServerTrusted(
							java.security.cert.X509Certificate[] certs, String authType)
					{
					}
				}
		};

		// Install the all-trusting trust manager
		try
		{
			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		}
		catch (GeneralSecurityException e)
		{
		}
		try
		{
			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		}
		catch (GeneralSecurityException e)
		{
		}

		try
		{
			final Field theFactory = javax.net.ssl.SSLSocketFactory.class.getDeclaredField("theFactory");
			theFactory.setAccessible(true);

			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());

			theFactory.set(null, sc.getSocketFactory());
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	private static void trustAllCertificatesOld()
	{
		com.sun.net.ssl.TrustManager[] trustAllCerts = new com.sun.net.ssl.TrustManager[]{
				new com.sun.net.ssl.X509TrustManager()
				{

					@Override
					public boolean isClientTrusted(X509Certificate[] x509Certificates)
					{
						return true;
					}

					@Override
					public boolean isServerTrusted(X509Certificate[] x509Certificates)
					{
						return true;
					}

					@Override
					public X509Certificate[] getAcceptedIssuers()
					{
						return new X509Certificate[0];
					}
				}
		};

		// Install the all-trusting trust manager
		try
		{
			com.sun.net.ssl.SSLContext sc = com.sun.net.ssl.SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			com.sun.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		}
		catch (GeneralSecurityException e)
		{
		}
		try
		{
			com.sun.net.ssl.SSLContext sc = com.sun.net.ssl.SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			com.sun.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		}
		catch (GeneralSecurityException e)
		{
		}
	}
}
