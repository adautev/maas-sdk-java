package com.miracl.maas_samples;

import com.miracl.maas_sdk.MiraclClient;
import com.mitchellbosecke.pebble.PebbleEngine;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import spark.ModelAndView;
import spark.Session;
import spark.TemplateEngine;
import spark.template.pebble.PebbleTemplateEngine;

import static spark.Spark.get;

public class SparkSample
{

	public static final String CLIENT_ID = "CLIENT_ID";
	public static final String CLIENT_SECRET = "CLIENT_SECRET";
	public static final String REDIRECT_URL = "REDIRECT_URL";

	public static ModelAndView renderTemplate(Session session, Map<String, Object> data)
	{
		Map<String, Object> params = new HashMap<>(data);
		params.put("messages", session.attribute("messages"));
		session.removeAttribute("messages");
		if (!params.containsKey("retry"))
		{
			params.put("retry", false);
		}
		if (!params.containsKey("authorized"))
		{
			params.put("authorized", false);
		}
		return new ModelAndView(params, "templates/index.pebble");
	}

	public static void flashMessage(Session session, String category, String message)
	{
		ArrayList<Map<String, String>> messages = session.attribute("messages");
		if (messages == null)
		{
			messages = new ArrayList<>();
		}

		final HashMap<String, String> messageMap = new HashMap<>();
		messageMap.put("category", category);
		messageMap.put("message", message);
		messages.add(messageMap);
		session.attribute("messages", messages);
	}

	public static void main(String[] args)
	{
		//TODO: Remove when not needed - temporary workaround
		trustAllCertificatesOld();
		trustAllCertificatesNew();


		final PebbleEngine pebbleEngine = new PebbleEngine(new ResourcesLoader());
		pebbleEngine.setStrictVariables(true);
		final TemplateEngine templateEngine = new PebbleTemplateEngine(pebbleEngine);
		MiraclClient miracl = new MiraclClient(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL);
		get("/", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			Map<String, Object> data = new HashMap<>();

			final boolean authorized = miracl.isAuthorized(preserver);
			data.put("authorized", authorized);

			if (authorized)
			{
				data.put("email", miracl.getEmail(preserver));
				data.put("userId", miracl.getUserId(preserver));
			}
			else
			{
				data.put("authURL", miracl.getAuthorizationRequestUrl(preserver));
			}

			return renderTemplate(req.session(), data);
		}, templateEngine);

		get("/c2id", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			Map<String, Object> data = new HashMap<>();

			final String token = miracl.validateAuthorization(preserver, req.queryString());
			if (token != null)
			{
				flashMessage(req.session(), "success", "Successfully logged in");
				res.redirect("/");

			}
			else
			{
				flashMessage(req.session(), "danger", "Login failed!");
				data.put("retry", true);
				data.put("authURL", miracl.getAuthorizationRequestUrl(preserver));
			}

			return renderTemplate(req.session(), data);
		}, templateEngine);


		get("/refresh", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			miracl.clearUserInfo(preserver);
			res.redirect("/");
			return "";
		});

		get("/logout", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			miracl.clearUserInfoAndSession(preserver);
			flashMessage(req.session(), "info", "User logged out!");
			res.redirect("/");
			return "";
		});
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
