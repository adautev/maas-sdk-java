package com.miracl.maas_samples;

import com.miracl.maas_sdk.MiraclClient;
import com.mitchellbosecke.pebble.PebbleEngine;

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
		final PebbleEngine pebbleEngine = new PebbleEngine(new ResourcesLoader());
		pebbleEngine.setStrictVariables(true);
		final TemplateEngine templateEngine = new PebbleTemplateEngine(pebbleEngine);

		MiraclClient miracl = new MiraclClient("CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URL");
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
				data.put("retry", "true");
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
			flashMessage(req.session(), "info", "User logged out");
			res.redirect("/");
			return "";
		});

	}
}
