package com.miracl.maas_samples;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.miracl.maas_sdk.*;
import com.mitchellbosecke.pebble.PebbleEngine;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import spark.ModelAndView;
import spark.Request;
import spark.Response;
import spark.Session;
import spark.TemplateEngine;
import spark.template.pebble.PebbleTemplateEngine;

import static spark.Spark.*;

/**
 * Main class of sample application.
 */
public class SparkSamplePV {
    private static final String MESSAGES_ATTRIBUTE = "messages";
	private static final String RETRY_ATTRIBUTE = "retry";
	private static final String AUTHORIZED_ATTRIBUTE = "authorized";
	private static final String ROOT_URL = "/";
    private static final int PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE = 404;
    private static final int PUSH_VERIFICATION_SUCCESSFUL_STATUS_CODE = 200;
	private static final int DEFAULT_HOST = 5000;
	private static final String DEFAULT_PROXY_HOST = "localhost";
	private static final String DEFAULT_PROXY_PORT = "8888";
	private static final HashMap<String, IdentityActivationModel> usersWaitingForActivation = new HashMap<>();
	private static final Logger LOGGER = Logger.getLogger(SparkSamplePV.class.getName());
    private static final String NEW_USER_TOKEN_KEY = "new_user_token";
    private static PLUGGABLE_VERIFICATION_MODE pluggableVerificationMethod;

    private enum PLUGGABLE_VERIFICATION_MODE {
    	PUSH, PULL
	}

    private SparkSamplePV() {
	}

	/**
	 * Utility function to prepare model and view for page rendering.
	 *
	 * @param session
	 *            Session for retrieving user-visible messages
	 * @param data
	 *            Data for template.
	 * @return view and model to be rendered
	 */
	public static ModelAndView prepareModelAndView(Session session, Map<String, Object> data) {
		// Create model with data passed to function
		Map<String, Object> params = new HashMap<>(data);

		// Add messages from session to model
		params.put(MESSAGES_ATTRIBUTE, session.attribute(MESSAGES_ATTRIBUTE));
		// Clean messages from session (consider messages viewed)
		session.removeAttribute(MESSAGES_ATTRIBUTE);

		// Add missing flags (defaulting to false)
		if (!params.containsKey(RETRY_ATTRIBUTE)) {
			params.put(RETRY_ATTRIBUTE, false);
		}
		if (!params.containsKey(AUTHORIZED_ATTRIBUTE)) {
			params.put(AUTHORIZED_ATTRIBUTE, false);
		}

		return new ModelAndView(params, "templates/index.pebble");
	}

	/**
	 * Utility function to save user-visible messages to session for later
	 * display.
	 *
	 * @param session
	 *            Session
	 * @param category
	 *            Category of message. Default Bootstrap categories are:
	 *            success, info, warning, danger
	 * @param message
	 *            Message text
	 */
	public static void flashMessage(Session session, String category, String message) {
		// Retrieving messages from session
		ArrayList<Map<String, String>> messages = session.attribute(MESSAGES_ATTRIBUTE);

		// Creating new list if session did not contain messages
		if (messages == null) {
			messages = new ArrayList<>();
		}

		// Creating message object
		final HashMap<String, String> messageMap = new HashMap<>();
		messageMap.put("category", category);
		messageMap.put("message", message);

		// Adding message to messages list
		messages.add(messageMap);

		// Setting sessions messages to new messages list
		session.attribute(MESSAGES_ATTRIBUTE, messages);
	}

	// Main request handler - show login button or user data
	private static ModelAndView handleMainRequest(MiraclClient client, Request req) {
		// Construct session wrapper for Miracl
		final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());

		// Model data for template
		Map<String, Object> data = new HashMap<>();

		// Check if session have information about user
		final boolean authorized = client.isAuthorized(preserver);
		data.put(AUTHORIZED_ATTRIBUTE, authorized);

		if (authorized) {
			// Put user data into model for display
			data.put("email", client.getEmail(preserver));
			data.put("userId", client.getUserId(preserver));
		} else {
			// Put authURL into model for creation of login button
			data.put("authURL", client.getAuthorizationRequestUrl(preserver));
		}

		// return model and view for template rendering
		return prepareModelAndView(req.session(), data);
	}

	// Callback handler - process callback from login process
	private static ModelAndView handleLoginRequest(MiraclClient client, Request req, Response resp) {
		// Construct session wrapper for Miracl
		final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());

		// Model data for template
		Map<String, Object> data = new HashMap<>();

		// Request validation of authorization data, retrieving token
		final String token = client.validateAuthorization(preserver, req.queryString());

		if (token == null) {
			return failLogin(client, preserver, req, resp);
		}

		// Validate the JWT you received
		try {
			JwtValidator validator = new JwtValidator("RS256");
			validator.validateToken(token);
		} catch (MiraclException e) {
			LOGGER.log(Level.SEVERE, e.getMessage(), e);
			return failLogin(client, preserver, req, resp);
		}

		// Prepare model and view before setting message
		final ModelAndView modelAndView = prepareModelAndView(req.session(), data);
		// Show message about successful log in
		flashMessage(req.session(), "success", "Successfully logged in");
		// and redirect back to start
		resp.redirect(ROOT_URL);
		// return model and view for template rendering
		return modelAndView;
	}

	// Prepare a ModelAndView for returning whenever logging in failed
	private static ModelAndView failLogin(MiraclClient client, MiraclSparkSessionWrapper preserver, Request req,
			Response resp) {

		// Model data for template
		Map<String, Object> data = new HashMap<>();

		// Show message about fail to log in
		flashMessage(req.session(), "danger", "Login failed!");

		data.put(RETRY_ATTRIBUTE, true);
		data.put("authURL", client.getAuthorizationRequestUrl(preserver));

		// return model and view for template rendering
		return prepareModelAndView(req.session(), data);
	}

	// Refresh handler - refresh user data and redirect back to beginning
	private static String handleRefreshRequest(MiraclClient client, Request req, Response resp) {
		// Construct session wrapper for Miracl
		final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
		// Clear user info. It will be re-retrieved when requested
		client.clearUserInfo(preserver);
		// Redirect back to start
		resp.redirect(ROOT_URL);
		// Return nothing to render as redirect already have prepared response
		return "";
	}

	// Logout handler - log out user and redirect back to beginning
	private static String handleLogoutRequest(MiraclClient client, Request req, Response resp) {
		// Constructing session wrapper for Miracl
		final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
		// Clear user info and related session entries
		client.clearUserInfoAndSession(preserver);
		// Notify user about log out
		flashMessage(req.session(), "info", "User logged out!");
		// Redirect back to start
		resp.redirect(ROOT_URL);
		// Return nothing to render as redirect already have prepared response
		return "";
	}

	// Read the JSON-formatted configuration data stored in miracl.json.
	private static JsonObject readConfiguration() throws IOException {
		String confFilename = "miracl.json";
		// Read configuration from miracl.json file for Miracl client
		// construction
		try (InputStream configStream = SparkSamplePV.class.getClassLoader().getResourceAsStream(confFilename)) {
			return Json.parse(new InputStreamReader(configStream)).asObject();
		}
	}

	public static void main(String[] args) throws IOException {
		final JsonObject config = readConfiguration();

		pluggableVerificationMethod = PLUGGABLE_VERIFICATION_MODE.PULL;
		String clientId = config.get("client_id").asString();
		String secret = config.get("secret").asString();
		String redirectUri = config.get("redirect_uri").asString();
		int serverPort = config.getInt("serverPort", DEFAULT_HOST);

		boolean useProxy = config.getBoolean("use_proxy", false);
		String proxyHost = config.getString("proxy_host", DEFAULT_PROXY_HOST);
		String proxyPort = config.getString("proxy_port", DEFAULT_PROXY_PORT);

		// Prepare template engine
		final PebbleEngine pebbleEngine = new PebbleEngine(new ResourcesLoader());
		pebbleEngine.setStrictVariables(true);
		final TemplateEngine templateEngine = new PebbleTemplateEngine(pebbleEngine);

		// Set Spark port
		port(serverPort);

		// Prepare Miracl client instance
		MiraclClient miracl = new MiraclClient(clientId, secret, redirectUri);

		if (useProxy) {
			MiraclClient.useProxy(proxyHost, proxyPort);
		}

		get(ROOT_URL, (req, res) -> handleMainRequest(miracl, req), templateEngine);
		get("/login", (req, res) -> handleLoginRequest(miracl, req, res), templateEngine);
		get("/refresh", (req, res) -> handleRefreshRequest(miracl, req, res));
		get("/logout", (req, res) -> handleLogoutRequest(miracl, req, res));
		post("/push-the-tempo", (req, res) -> handlePushVerification(miracl, req, res));
		put("/activate-pushed-user/:sub", (req, res) -> handleUserActivation(miracl, req, res));
	}

    /**
     * Activates an identity subject to a pluggable verification process
     * @param miracl A {@link MiraclClient} instance.
     * @param req A {@link Request} instance, containing all HTTP request specific information.
     * @param res A {@link Response} instance, used for response behavior modification.
     * @return
     */

    private static String handleUserActivation(MiraclClient miracl, Request req, Response res) {
	    String subject = req.params(":sub");
        res.status(PUSH_VERIFICATION_SUCCESSFUL_STATUS_CODE);

        if(pluggableVerificationMethod == PLUGGABLE_VERIFICATION_MODE.PULL) {
            try {
                IdentityActivationModel activationData = miracl.pullVerification(subject, MiraclClient.getPluggableVerificationPullEndpointURL());
                usersWaitingForActivation.put(activationData.getSubject(), activationData);
            } catch (MiraclClientException ex) {
                LOGGER.log(Level.SEVERE, String.format("Unable to perform a pluggable verification pull request for subject %s", subject), ex);
                res.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
                return "";
            }
        }
	    if(!usersWaitingForActivation.containsKey(subject)) {
            res.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
        } else {
            try {
                miracl.activateIdentity(usersWaitingForActivation.get(subject), MiraclClient.getClientActivationEndpointURL());
            } catch (Exception ex) {
                LOGGER.log(Level.SEVERE, String.format("Unable to activate identity subject %s", subject), ex);
                res.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
            }

        }
        return "";
    }

    /**
     * Validates a pluggable verification token contained in the request body and stores the information in memory.
     * @param miracl A {@link MiraclClient} instance.
     * @param req A {@link Request} instance, containing all HTTP request specific information.
     * @param resp A {@link Response} instance, used for response behavior modification.
     * @return
     */
    private static String handlePushVerification(MiraclClient miracl, Request req, Response resp) {
        resp.status(PUSH_VERIFICATION_SUCCESSFUL_STATUS_CODE);

        JsonObject tokenBody = Json.parse(req.body()).asObject();

        String newUserToken = tokenBody.get(NEW_USER_TOKEN_KEY).asString();
        String signingAlgorithm;
        try {
             signingAlgorithm = miracl.getJWTSigningAlgorithm(newUserToken);
        } catch (MiraclClientException ex) {
            LOGGER.log(Level.SEVERE, "Unable to get the JSON Web Token signing algorithm.", ex);
            resp.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
            return "";
        }

        if(tokenBody == null || newUserToken == "") {
            resp.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
            return "";
        }

        if(!miracl.validatePushToken(newUserToken, signingAlgorithm)) {
            resp.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
            return "";
        } else {
            try {
                IdentityActivationModel identityActivationModel = miracl.getIdentityActivationModel(newUserToken, signingAlgorithm);
                usersWaitingForActivation.put(identityActivationModel.getSubject(), identityActivationModel);
            } catch (Exception ex) {
                resp.status(PLUGGABLE_VERIFICATION_NOT_SUCCESSFUL_STATUS_CODE);
                LOGGER.log(Level.SEVERE, "Unable to extract claims from the JSON Web Token", ex);
                return "";
            }
        }
		return "";
	}
}
