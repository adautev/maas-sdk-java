package com.miracl.maas_sdk;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Base64;
import java.util.Date;
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
    private static final int PLUGGABLE_VERIFICATION_ACTIVATION_ERROR_STATUS_CODE = 404;
    private static final int PLUGGABLE_VERIFICATION_PULL_ERROR_STATUS_CODE = 404;
    private static final int PLUGGABLE_VERIFICATION_PULL_UNAUTHORIZED_STATUS_CODE = 400;
    private static final String PLUGGABLE_VERIFICATION_ACTIVATION_REQUEST_HTTP_CONTENT_TYPE = "application/json";
    private static final String PLUGGABLE_VERIFICATION_PULL_REQUEST_HTTP_CONTENT_TYPE = "application/json";
    private static final String PLUGGABLE_VERIFICATION_PULL_USER_ID_FIELD_KEY = "userId";
    private static final String PLUGGABLE_VERIFICATION_PUSH_REQUEST_NEW_USER_TOKEN_KEY = "new_user_token";
    private static final String ALG_HEADER_KEY = "alg";


    private final ClientID clientId;
    private final Secret clientSecret;
    private final URI redirectUrl;
    private final OIDCProviderMetadata providerMetadata;
    private String providerInfo;

    /**
     * @param clientId     Client ID
     * @param clientSecret Client secret
     * @param redirectUrl  Redirect URL
     * @throws MiraclException if parameters can't be parsed
     */
    public MiraclClient(String clientId, String clientSecret, String redirectUrl) {
        this(clientId, clientSecret, redirectUrl, MiraclConfig.ISSUER);
    }

    /**
     * @param clientId     Client ID
     * @param clientSecret Client secret
     * @param redirectUrl  Redirect URL
     * @param issuer       Issuer URL
     * @throws MiraclException if parameters can't be parsed
     */
    public MiraclClient(String clientId, String clientSecret, String redirectUrl, String issuer) {
        try {
            this.clientId = new ClientID(clientId);
            this.clientSecret = new Secret(clientSecret);
            this.redirectUrl = new URI(redirectUrl);
            providerMetadata = getProviderMetadata(issuer);

        } catch (URISyntaxException | ParseException | IOException e) {
            throw new MiraclSystemException(e);
        }
    }

    /**
     * Forms a pluggable verification pull endpoint URL, according to the current MiraclConfig values.
     *
     * @return A pluggable verification pull endpoint fully qualified URL
     */
    public static String getPluggableVerificationPullEndpointURL() {
        return String.format("%s%s", MiraclConfig.ISSUER, MiraclConfig.PLUGGABLE_VERIFICATION_PULL_ENDPOINT);
    }

    /**
     * Perform a Provider Configuration Request to the issuer, returning its
     * metadata.
     *
     * @param issuer Issuer URL
     * @return provider configuration metadata
     * @throws URISyntaxException
     * @throws IOException
     * @throws ParseException
     * @see <a href=
     * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest">OpenID
     * Connect Discovery</a>
     */
    public OIDCProviderMetadata getProviderMetadata(String issuer)
            throws URISyntaxException, IOException, ParseException {
        URI issuerURI = new URI(issuer);
        URL providerConfigurationURL = issuerURI.resolve(MiraclConfig.OPENID_CONFIG_ENDPOINT).toURL();
        providerInfo = requestProviderInfo(providerConfigurationURL);

        return OIDCProviderMetadata.parse(providerInfo);
    }

    /**
     * Use a proxy for all out-going requests performed by the library.
     * <p>
     * If a proxy server is required, useProxy should be called immediately
     * after constructing a MiraclClient. Proxy settings are applied VM-wide.
     * The proxy will be used for both HTTP and HTTPS requests.
     *
     * @param host Hostname for the proxy server, for example "localhost"
     * @param port Port for the proxy server
     */
    public static void useProxy(String host, String port) {
        System.setProperty("http.proxyHost", host);
        System.setProperty("https.proxyHost", host);
        System.setProperty("http.proxyPort", port);
        System.setProperty("https.proxyPort", port);
    }

    /**
     * @param url URL pointing to openid-configuration
     * @return String containing contents of URL
     * @throws IOException In case of network issues
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
     * @param preserver Miracl preserver object for current user
     * @return Request URI for mpin authorization. After request redirects back,
     * pass queryString to
     * {@link #validateAuthorization(MiraclStatePreserver, String)} to
     * complete authorization with server.
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
     * @param preserver   Miracl preserver object for current user
     * @param queryString query string from request on redirectUrl
     * @return Token
     * @throws MiraclClientException if there is problem with token request
     * @throws MiraclSystemException if failure occurred while communicating with server
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
     * @return
     * @throws MiraclClientException If the response could not be parsed into an
     *                               AuthenticationResponse
     */
    protected AuthenticationResponse parseAuthenticationResponse(URI queryUri) {
        try {
            return AuthenticationResponseParser.parse(queryUri);
        } catch (ParseException e) {
            throw new MiraclClientException(e);
        }
    }

    /**
     * @param authorizationCode Authorization code from authorization query
     * @return Access token as string
     * @throws IOException    In case of network issues
     * @throws ParseException In case of incorrect answer from backend
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
     *
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
     * @param preserver Miracl preserver object for current user
     * @see #clearUserInfoAndSession(MiraclStatePreserver) to remove session
     * info
     */
    public void clearUserInfo(MiraclStatePreserver preserver) {
        preserver.remove(KEY_USERINFO);
    }

    /**
     * Clears user and session info from {@link MiraclStatePreserver preserver}
     *
     * @param preserver Miracl preserver object for current user
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
     * @param token Auth token (used in Bearer access header)
     * @return User info
     * @throws IOException    In case of network issues
     * @throws ParseException In case of incorrect answer from backend
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
     * @param request Request to send
     * @return A user info response
     * @throws IOException    If an HTTP request could not be made
     * @throws ParseException If the response could not be parsed into a UserInfoResponse
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
     * @param preserver Miracl preserver object for current user
     * @return if user associated with {@link MiraclStatePreserver preserver} is
     * authorized
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
     * @param preserver Miracl preserver object for current user
     * @return User e-mail
     * @throws MiraclClientException if there is problem with request
     * @throws MiraclSystemException if failure occurred while communicating with server
     * @see #getUserId(MiraclStatePreserver) for requesting user ID
     */
    public String getEmail(MiraclStatePreserver preserver) {
        UserInfo userInfo = getUserInfo(preserver);
        String email = userInfo.getStringClaim("email");
        return email == null ? "" : email;
    }

    /**
     * Get user id. This method can block while performing request to Miracl
     * system
     *
     * @param preserver Miracl preserver object for current user
     * @return User id
     * @throws MiraclClientException if there is problem with request
     * @throws MiraclSystemException if failure occurred while communicating with server
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

    /**
     * Extracts the required data for an identity activation on MIRACL trust, based on the data in the JWT supplied during push pluggable verification.
     *
     * @param requestBody the HTTP Request body
     * @return
     */
    public IdentityActivationModel getIdentityActivationModelForRequest(String requestBody) {
        JsonObject tokenBody = null;
        try {
            tokenBody = Json.parse(requestBody).asObject();
        }  catch (Exception ex) {
            LOGGER.log(Level.SEVERE, String.format(MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_JSON_OBJECT_FROM_REQUEST_BODY_LOG, requestBody));
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_JSON_OBJECT_FROM_REQUEST_BODY);
        }

        JsonValue newUserTokenObject = tokenBody.get(PLUGGABLE_VERIFICATION_PUSH_REQUEST_NEW_USER_TOKEN_KEY);
        if(newUserTokenObject == null){
            LOGGER.log(Level.SEVERE, String.format(MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY_LOG, requestBody));
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY);
        }

        String newUserToken = newUserTokenObject.asString();
        if(newUserToken.equals("")){
            LOGGER.log(Level.SEVERE, String.format(MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY_LOG, requestBody));
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_EXTRACT_NEW_USER_TOKEN_FROM_REQUEST_BODY);
        }

        String signingAlgorithm;
        try {
            signingAlgorithm = getJWTSigningAlgorithm(newUserToken);
        } catch (MiraclClientException ex) {
            LOGGER.log(Level.SEVERE, MiraclMessages.MIRACL_CLIENT_PV_PUSH_UNABLE_TO_GET_THE_JSON_WEB_TOKEN_SIGNING_ALGORITHM_LOG, ex);
            throw ex;
        }

        JwtValidator validator = new JwtValidator(signingAlgorithm);
        validator.validatePushToken(newUserToken);
        if (!validator.validatePushToken(newUserToken)) {
            LOGGER.log(Level.SEVERE, String.format(MiraclMessages.MIRACL_CLIENT_PV_PUSH_INVALID_PUSH_TOKEN_IN_THE_REQUEST_BODY_LOG, requestBody));
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PUSH_INVALID_PUSH_TOKEN_IN_THE_REQUEST_BODY);
        }

        JWTClaimsSet tokenSet;
        try {
            tokenSet = validator.extractClaims(newUserToken);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Unable to extract claims from JWT.", e);
            throw new MiraclClientException("Unable to extract claims from JWT.");
        }

        JSONObject eventsClaim = (JSONObject) tokenSet.getClaim("events");
        if (eventsClaim == null) {
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PUSH_EVENTS_KEY_NOT_FOUND_IN_ACTIVATION_JWT);
        }

        Object newUser = eventsClaim.get("newUser");
        if (newUser == null) {
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PUSH_NEW_USER_KEY_NOT_FOUND_IN_ACTIVATION_JWT);
        }

        String mpinIdHash = ((JSONObject) newUser).getAsString(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH);
        String activationKey = ((JSONObject) newUser).getAsString(IdentityActivationModel.ACTIVATION_KEY);
        String subject = ((JSONObject) newUser).getAsString(IdentityActivationModel.USER_ID_KEY_PUSH);
        return new IdentityActivationModel(mpinIdHash, activationKey, subject);
    }


    /**
     * Extracts signing algorithm from signed JWT header.
     *
     * @param jwt The full JWT
     * @return {@link JWSAlgorithm}
     * @throws MiraclClientException
     */
    String getJWTSigningAlgorithm(String jwt) throws MiraclClientException {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_INVALID_JWT);
        }
        JSONObject headerJSON = (JSONObject) JSONValue.parse(Base64.getDecoder().decode(parts[0]));
        if (headerJSON == null) {
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_UNABLE_TO_PARSE_JWT_HEADER);
        }
        if (!headerJSON.containsKey("alg")) {
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_GET_SIGNING_ALGORITHM_SIGNING_ALGORITHM_NOT_SPECIFIED_IN_JWT_HEADER);
        }
        return JWSAlgorithm.parse(headerJSON.getAsString(ALG_HEADER_KEY)).getName();
    }

    /**
     * Activates an identity that is a subject to pluggable verification
     *  @param identityActivationModel A {@link IdentityActivationModel} instance with valid client activation parameters.
     *
     */
    public void activateIdentity(IdentityActivationModel identityActivationModel) {

        try {
            HTTPRequest activationRequest = new HTTPRequest(HTTPRequest.Method.POST,
                    new URL(getClientActivationEndpointURL())
            );
            activationRequest.setAuthorization(getClientCredentials());
            activationRequest.setContentType(PLUGGABLE_VERIFICATION_ACTIVATION_REQUEST_HTTP_CONTENT_TYPE);
            JSONObject activationRequestBody = new JSONObject();
            activationRequestBody.appendField(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH, identityActivationModel.getМPinIdHash());
            activationRequestBody.appendField(IdentityActivationModel.ACTIVATION_KEY, identityActivationModel.getActivationKey());
            activationRequest.setQuery(activationRequestBody.toJSONString());
            HTTPResponse response = activationRequest.send();
            if (response.getStatusCode() == PLUGGABLE_VERIFICATION_ACTIVATION_ERROR_STATUS_CODE) {
                throw new MiraclClientException("An error occured while activating user.");
            }
        } catch (MalformedURLException | ParseException e) {
            LOGGER.log(Level.SEVERE, MiraclMessages.MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_CREATE_ACTIVATION_POST_REQUEST_LOG, e);
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_CREATE_ACTIVATION_POST_REQUEST);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, MiraclMessages.MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_EXECUTE_ACTIVATION_POST_REQUEST_LOG, e);
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_ACTIVATE_UNABLE_TO_EXECUTE_ACTIVATION_POST_REQUEST);
        }

    }

    /**
     * Activates an identity that is a subject to pluggable verification
     *  @param subject A unique identity identifier
     *
     */
    public IdentityActivationModel pullVerification(String subject) {

        try {
            HTTPRequest pullRequest = new HTTPRequest(HTTPRequest.Method.POST,
                    new URL(MiraclClient.getPluggableVerificationPullEndpointURL())
            );
            pullRequest.setAuthorization(getClientCredentials());
            pullRequest.setContentType(PLUGGABLE_VERIFICATION_PULL_REQUEST_HTTP_CONTENT_TYPE);
            JSONObject pullRequestBody = new JSONObject();
            pullRequestBody.appendField(PLUGGABLE_VERIFICATION_PULL_USER_ID_FIELD_KEY, subject);
            pullRequest.setQuery(pullRequestBody.toJSONString());
            HTTPResponse response = pullRequest.send();

            if (response.getStatusCode() == PLUGGABLE_VERIFICATION_PULL_ERROR_STATUS_CODE) {
                throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_ERROR_OCCURED_WHILE_EXECUTING_REQUEST);
            }
            if (response.getStatusCode() == PLUGGABLE_VERIFICATION_PULL_UNAUTHORIZED_STATUS_CODE) {
                throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_UNABLE_TO_AUTHENTICATE);
            }

            JSONObject responseBody = response.getContentAsJSONObject();
            String mpinIdHash = responseBody.getAsString(IdentityActivationModel.MPIN_ID_HASH_KEY);
            String activationKey = responseBody.getAsString(IdentityActivationModel.ACTIVATION_KEY);
            //convert second based epoch value to milliseconds
            Date expirationTime = new Date(responseBody.getAsNumber(IdentityActivationModel.EXPIRATION_TIME).longValue() * 1000);

            if (mpinIdHash == null || mpinIdHash.equals("")) {
                throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_MPIN_ID_NOT_FOUND);
            }

            if (activationKey == null || activationKey.equals("")) {
                throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_ACTIVATION_KEY_NOT_FOUND);
            }

            if (expirationTime.before(new Date())) {
                throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_REQUEST_EXPIRED);
            }
            return new IdentityActivationModel(mpinIdHash, activationKey, subject);
        } catch (MalformedURLException | ParseException e) {
            LOGGER.log(Level.SEVERE, MiraclMessages.MIRACL_CLIENT_PV_PULL_UNABLE_TO_CREATE_POST_REQUEST, e);
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_UNABLE_TO_CREATE_POST_REQUEST);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, MiraclMessages.MIRACL_CLIENT_PV_PULL_UNABLE_TO_EXECUTE_POST_REQUEST, e);
            throw new MiraclClientException(MiraclMessages.MIRACL_CLIENT_PV_PULL_UNABLE_TO_EXECUTE_POST_REQUEST);
        }
    }

    protected String getClientActivationEndpointURL() {
        return String.format("%s%s", MiraclConfig.ISSUER, MiraclConfig.PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT);
    }

    /**
     * Creates a client-id:client-secret base64 encoded client credentials string.
     *
     * @return a client-id:client-secret base64 encoded client credentials string.
     */
    private String getClientCredentials() {
        return String.format("Basic %s",
                Base64.getEncoder().encodeToString(String.format("%s:%s", clientId, clientSecret.getValue()).getBytes())
        );
    }
}
