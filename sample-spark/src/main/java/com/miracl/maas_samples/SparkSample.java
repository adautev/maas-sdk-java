package com.miracl.maas_samples;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.miracl.maas_sdk.MiraclClient;
import com.mitchellbosecke.pebble.PebbleEngine;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import spark.ModelAndView;
import spark.Session;
import spark.TemplateEngine;
import spark.template.pebble.PebbleTemplateEngine;

import static spark.Spark.get;
import static spark.Spark.port;

/**
 * Main class of sample application.
 */
public class SparkSample
{
	/**
	 * Utility function to prepare model and view for page rendering.
	 *
	 * @param session Session for retrieving user-visible messages
	 * @param data    Data for template.
	 * @return view and model to be rendered
	 */
	public static ModelAndView prepareModelAndView(Session session, Map<String, Object> data)
	{
		// Create model with data passed to function
		Map<String, Object> params = new HashMap<>(data);

		// Add messages from session to model
		params.put("messages", session.attribute("messages"));
		// Clean messages from session (consider messages viewed)
		session.removeAttribute("messages");

		// Add missing flags (defaulting to false)
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

	/**
	 * Utility function to save user-visible messages to session for later display.
	 *
	 * @param session  Session
	 * @param category Category of message. Default Bootstrap categories are: success, info, warning, danger
	 * @param message  Message text
	 */
	public static void flashMessage(Session session, String category, String message)
	{
		// Retrieving messages from session
		ArrayList<Map<String, String>> messages = session.attribute("messages");
		// Creating new list if session did not contain messages
		if (messages == null)
		{
			messages = new ArrayList<>();
		}

		// Creating message object
		final HashMap<String, String> messageMap = new HashMap<>();
		messageMap.put("category", category);
		messageMap.put("message", message);
		// Adding message to messages list
		messages.add(messageMap);
		// Setting sessions messages to new messages list
		session.attribute("messages", messages);
	}

	public static void main(String[] args) throws IOException
	{
		// Read configuration from miracl.json file for Miracl client construction
		final InputStream configStream = SparkSample.class.getClassLoader().getResourceAsStream("miracl.json");
		final JsonObject config = Json.parse(new InputStreamReader(configStream)).asObject();
		String clientId = config.get("client_id").asString();
		String secret = config.get("secret").asString();
		String redirectUri = config.get("redirect_uri").asString();
		configStream.close();

		// Prepare template engine
		final PebbleEngine pebbleEngine = new PebbleEngine(new ResourcesLoader());
		pebbleEngine.setStrictVariables(true);
		final TemplateEngine templateEngine = new PebbleTemplateEngine(pebbleEngine);

		// Set Spark port
		port(5000);

		// Prepare Miracl client instance
		MiraclClient miracl = new MiraclClient(clientId, secret, redirectUri);

		// Main request handler - show login button or user data
		get("/", (req, res) ->
		{
			// Construct session wrapper for Miracl
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());

			// Model data for template
			Map<String, Object> data = new HashMap<>();

			// Check if session have information about user
			final boolean authorized = miracl.isAuthorized(preserver);
			data.put("authorized", authorized);

			if (authorized)
			{
				// Put user data into model for display
				data.put("email", miracl.getEmail(preserver));
				data.put("userId", miracl.getUserId(preserver));
			}
			else
			{
				// Put authURL into model for creation of login button
				data.put("authURL", miracl.getAuthorizationRequestUrl(preserver));
			}

			// return model and view for template rendering
			return prepareModelAndView(req.session(), data);
		}, templateEngine);

		// Callback handler - process callback from login process
		get("/login", (req, res) ->
		{
			// Construct session wrapper for Miracl
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());

			// Model data for template
			Map<String, Object> data = new HashMap<>();

			// Request validation of authorization data, retrieving token
			final String token = miracl.validateAuthorization(preserver, req.queryString());

			if (token != null)
			{
				// Prepare model and view before setting message
				final ModelAndView modelAndView = prepareModelAndView(req.session(), data);
				// Show message about successful log in
				flashMessage(req.session(), "success", "Successfully logged in");
				// and redirect back to start
				res.redirect("/");
				// return model and view for template rendering
				return modelAndView;
			}
			else
			{
				// Show message about fail to log in
				flashMessage(req.session(), "danger", "Login failed!");

				// Prepare model data to show login button for retry
				data.put("retry", true);
				data.put("authURL", miracl.getAuthorizationRequestUrl(preserver));
				// return model and view for template rendering
				return prepareModelAndView(req.session(), data);
			}
		}, templateEngine);


		// Refresh handler - refresh user data and redirect back to beginning
		get("/refresh", (req, res) ->
		{
			// Construct session wrapper for Miracl
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			// Clear user info. It will be re-retrieved when requested
			miracl.clearUserInfo(preserver);
			// Redirect back to start
			res.redirect("/");
			// Return nothing to render as redirect already have prepared response
			return "";
		});

		// Logout handler - log out user and redirect back to beginning
		get("/logout", (req, res) ->
		{
			// Constructing session wrapper for Miracl
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			// Clear user info and related session entries
			miracl.clearUserInfoAndSession(preserver);
			// Notify user about log out
			flashMessage(req.session(), "info", "User logged out!");
			// Redirect back to start
			res.redirect("/");
			// Return nothing to render as redirect already have prepared response
			return "";
		});
	}
}
