package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main class for interfacing with Miracl service.
 */
public class MiraclClient {
	private static final String KEY_STATE = "miracl_state";
	private static final String KEY_NONCE = "miracl_nonce";
	private static final String KEY_TOKEN = "miracl_token";
	private static final String KEY_USERINFO = "miracl_userinfo";

	private static final Logger LOGGER = Logger.getLogger(MiraclClient.class.getName());

	private final ClientID clientId;
	private final Secret clientSecret;
	private final URI redirectUrl;
	private final OIDCProviderMetadata providerMetadata;

	/**
	 * @param clientId
	 *            Client ID
	 * @param clientSecret
	 *            Client secret
	 * @param redirectUrl
	 *            Redirect URL
	 * @throws MiraclException
	 *             if parameters can't be parsed
	 */
	public MiraclClient(String clientId, String clientSecret, String redirectUrl) {
		this(clientId, clientSecret, redirectUrl, MiraclConfig.ISSUER);
	}

	/**
	 * @param clientId
	 *            Client ID
	 * @param clientSecret
	 *            Client secret
	 * @param redirectUrl
	 *            Redirect URL
	 * @param issuer
	 *            Issuer URL
	 * @throws MiraclException
	 *             if parameters can't be parsed
	 */
	public MiraclClient(String clientId, String clientSecret, String redirectUrl, String issuer) {
		this.clientId = new ClientID(clientId);
		this.clientSecret = new Secret(clientSecret);

		try {
			this.redirectUrl = new URI(redirectUrl);
			providerMetadata = getProviderMetadata(issuer);
		} catch (URISyntaxException | ParseException | IOException e) {
			throw new MiraclSystemException(e);
		}
	}

	/**
	 * Perform a Provider Configuration Request to the issuer, returning its
	 * metadata.
	 * 
	 * @see <a href=
	 *      "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
	 *      Connect Discovery</a>
	 * @param issuer
	 *            Issuer URL
	 * @return provider configuration metadata
	 * @throws URISyntaxException
	 * @throws IOException
	 * @throws ParseException
	 */
	private OIDCProviderMetadata getProviderMetadata(String issuer)
			throws URISyntaxException, IOException, ParseException {
		URI issuerURI = new URI(issuer);
		URL providerConfigurationURL = issuerURI.resolve(MiraclConfig.OPENID_CONFIG_ENDPOINT).toURL();
		String providerInfo = requestProviderInfo(providerConfigurationURL);

		return OIDCProviderMetadata.parse(providerInfo);
	}

	/**
	 * Use a proxy for all out-going requests performed by the library.
	 * 
	 * If a proxy server is required, useProxy should be called immediately
	 * after constructing a MiraclClient. Proxy settings are applied VM-wide.
	 * The proxy will be used for both HTTP and HTTPS requests.
	 * 
	 * @param host
	 *            Hostname for the proxy server, for example "localhost"
	 * @param port
	 *            Port for the proxy server
	 */
	public static void useProxy(String host, String port) {
		System.setProperty("http.proxyHost", host);
		System.setProperty("https.proxyHost", host);
		System.setProperty("http.proxyPort", port);
		System.setProperty("https.proxyPort", port);
	}

	/**
	 * @param url
	 *            URL pointing to openid-configuration
	 * @return String containing contents of URL
	 * @throws IOException
	 *             In case of network issues
	 */
	protected String requestProviderInfo(URL url) throws IOException {
		InputStream stream = url.openStream();

		String providerInfo = null;
		try (java.util.Scanner s = new java.util.Scanner(stream)) {
			providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
		}
		return providerInfo;
	}

	/**
	 * Get {@link URI} for authorization request. After user is redirected back
	 * (to redirect URL defined in constructor), call
	 * {@link #validateAuthorization(MiraclStatePreserver, String)} to complete
	 * authorization with server.
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @return Request URI for mpin authorization. After request redirects back,
	 *         pass queryString to
	 *         {@link #validateAuthorization(MiraclStatePreserver, String)} to
	 *         complete authorization with server.
	 */
	public URI getAuthorizationRequestUrl(MiraclStatePreserver preserver) {
		State state = new State();
		Nonce nonce = new Nonce();

		preserver.put(KEY_STATE, state.getValue());
		preserver.put(KEY_NONCE, nonce.getValue());

		Scope scope = new Scope();
		scope.add("openid");
		scope.add("sub");
		scope.add("email");

		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
				providerMetadata.getAuthorizationEndpointURI(), new ResponseType(ResponseType.Value.CODE), scope,
				clientId, redirectUrl, state, nonce);

		return authenticationRequest.toURI();
	}

	/**
	 * Completes authorization with server and returns access token. Access
	 * token is saved in {@link MiraclStatePreserver preserver} so usually it is
	 * not needed to save access token This method can block while performing
	 * request to Miracl system
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @param queryString
	 *            query string from request on redirectUrl
	 * @return Token
	 * @throws MiraclClientException
	 *             if there is problem with token request
	 * @throws MiraclSystemException
	 *             if failure occurred while communicating with server
	 */
	public String validateAuthorization(MiraclStatePreserver preserver, String queryString) {
		URI queryUri = buildAuthenticationUri(queryString);
		AuthenticationResponse response = parseAuthenticationResponse(queryUri);
		boolean isStateOk;
		String accessToken;

		validateNonErrorResponse(response);
		isStateOk = response.getState().toString().equals(preserver.get(KEY_STATE));

		if (!isStateOk) {
			return null;
		}

		try {
			accessToken = requestAccessToken(((AuthenticationSuccessResponse) response).getAuthorizationCode());
			preserver.put(KEY_TOKEN, accessToken);
			return accessToken;
		} catch (ParseException | IOException e) {
			LOGGER.log(Level.SEVERE, e.getMessage(), e);
			throw new MiraclSystemException(e);
		}
	}

	protected URI buildAuthenticationUri(String queryString) {
		return URI.create("/?" + queryString);
	}

	/**
	 * Attempt to parse an AuthenticationResponse
	 * 
	 * @param queryUri
	 * @throws MiraclClientException
	 *             If the response could not be parsed into an
	 *             AuthenticationResponse
	 * @return
	 */
	protected AuthenticationResponse parseAuthenticationResponse(URI queryUri) {
		try {
			return AuthenticationResponseParser.parse(queryUri);
		} catch (ParseException e) {
			throw new MiraclClientException(e);
		}
	}

	/**
	 * @param authorizationCode
	 *            Authorization code from authorization query
	 * @return Access token as string
	 * @throws IOException
	 *             In case of network issues
	 * @throws ParseException
	 *             In case of incorrect answer from backend
	 */
	protected String requestAccessToken(AuthorizationCode authorizationCode) throws IOException, ParseException {
		TokenRequest tokenRequest = buildTokenRequest(authorizationCode);
		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
		validateNonErrorResponse(tokenResponse);

		OIDCTokenResponse accessTokenResponse = (OIDCTokenResponse) tokenResponse;
		final AccessToken accessToken = accessTokenResponse.getOIDCTokens().getAccessToken();
		return accessToken.getValue();
	}

	/**
	 * Build a token request based on an authorization code
	 * 
	 * @param authorizationCode
	 * @return
	 */
	protected TokenRequest buildTokenRequest(AuthorizationCode authorizationCode) {
		return new TokenRequest(providerMetadata.getTokenEndpointURI(), new ClientSecretBasic(clientId, clientSecret),
				new AuthorizationCodeGrant(authorizationCode, redirectUrl));
	}
	
	/**
	 * Check that a {@link Response} is not an {@link ErrorResponse},
	 * throw a {@link MiraclClientException} if it is.
	 * @param response The Response to validate
	 * @throws MiraclClientException If the Response is an instance of ErrorResponse
	 */
	protected void validateNonErrorResponse(Response response) {
		if (response instanceof ErrorResponse) {
			ErrorObject error = ((ErrorResponse) response).getErrorObject();
			throw new MiraclClientException(error);
		}
	}

	/**
	 * Clears user info from {@link MiraclStatePreserver preserver}. Can be used
	 * to refresh user data before using
	 * {@link #getUserId(MiraclStatePreserver)} and
	 * {@link #getEmail(MiraclStatePreserver)}
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @see #clearUserInfoAndSession(MiraclStatePreserver) to remove session
	 *      info
	 */
	public void clearUserInfo(MiraclStatePreserver preserver) {
		preserver.remove(KEY_USERINFO);
	}

	/**
	 * Clears user and session info from {@link MiraclStatePreserver preserver}
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @see #clearUserInfo(MiraclStatePreserver) to remove only user info
	 */
	public void clearUserInfoAndSession(MiraclStatePreserver preserver) {
		clearUserInfo(preserver);
		preserver.remove(KEY_TOKEN);
	}

	private UserInfo getUserInfo(MiraclStatePreserver preserver) {
		if (preserver.get(KEY_TOKEN) == null) {
			throw new MiraclClientException(MiraclMessages.USER_NOT_AUTHORIZED);
		}

		if (preserver.get(KEY_USERINFO) != null) {
			final UserInfo userInfo;
			try {
				userInfo = UserInfo.parse(preserver.get(KEY_USERINFO));
				return userInfo;
			} catch (ParseException e) {
				// If problems with userinfo parsing, remove it and continue
				// with obtaining new userinfo
				preserver.remove(KEY_USERINFO);
			}
		}

		try {
			UserInfo userInfo = requestUserInfo(preserver.get(KEY_TOKEN));
			preserver.put(KEY_USERINFO, userInfo.toJSONObject().toJSONString());
			return userInfo;
		} catch (SerializeException | IOException | ParseException e) {
			throw new MiraclSystemException(e);
		}
	}

	/**
	 * @param token
	 *            Auth token (used in Bearer access header)
	 * @return User info
	 * @throws IOException
	 *             In case of network issues
	 * @throws ParseException
	 *             In case of incorrect answer from backend
	 */
	protected UserInfo requestUserInfo(String token) throws IOException, ParseException {
		final BearerAccessToken accessToken = new BearerAccessToken(token);
		UserInfoRequest userInfoReq = new UserInfoRequest(providerMetadata.getUserInfoEndpointURI(), accessToken);
		UserInfoResponse userInfoResponse = doUserInfoRequest(userInfoReq);
		validateNonErrorResponse(userInfoResponse);

		UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponse;
		return successResponse.getUserInfo();
	}

	/**
	 * Perform an HTTP request to retrieve user info.
	 * 
	 * @param request
	 *            Request to send
	 * @return A user info response
	 * @throws IOException
	 *             If an HTTP request could not be made
	 * @throws ParseException
	 *             If the response could not be parsed into a UserInfoResponse
	 */
	protected UserInfoResponse doUserInfoRequest(UserInfoRequest request) throws IOException, ParseException {
		HTTPResponse httpResponse = request.toHTTPRequest().send();
		return UserInfoResponse.parse(httpResponse);
	}

	/**
	 * Checks if token is in {@link MiraclStatePreserver preserver} and user
	 * data is accessible (by request or in cache). This method can block while
	 * performing request to Miracl system
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @return if user associated with {@link MiraclStatePreserver preserver} is
	 *         authorized
	 */
	public boolean isAuthorized(MiraclStatePreserver preserver) {
		try {
			return getUserInfo(preserver) != null;
		} catch (MiraclClientException e) {
			LOGGER.log(Level.FINER, e.getMessage(), e);
			return false;
		}
	}

	/**
	 * Get user e-mail. This method can block while performing request to Miracl
	 * system
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @return User e-mail
	 * @throws MiraclClientException
	 *             if there is problem with request
	 * @throws MiraclSystemException
	 *             if failure occurred while communicating with server
	 * @see #getUserId(MiraclStatePreserver) for requesting user ID
	 */
	public String getEmail(MiraclStatePreserver preserver) {
		final UserInfo userInfo = getUserInfo(preserver);
		if (userInfo == null) {
			return null;
		}

		final String email = userInfo.getStringClaim("email");
		return email == null ? "" : email;
	}

	/**
	 * Get user id. This method can block while performing request to Miracl
	 * system
	 *
	 * @param preserver
	 *            Miracl preserver object for current user
	 * @return User id
	 * @throws MiraclClientException
	 *             if there is problem with request
	 * @throws MiraclSystemException
	 *             if failure occurred while communicating with server
	 * @see #getEmail(MiraclStatePreserver) for requesting user e-mail
	 */
	public String getUserId(MiraclStatePreserver preserver) {
		final UserInfo userInfo = getUserInfo(preserver);
		if (userInfo == null) {
			return null;
		}

		final String sub = userInfo.getStringClaim("sub");
		return sub == null ? "" : sub;
	}
}
