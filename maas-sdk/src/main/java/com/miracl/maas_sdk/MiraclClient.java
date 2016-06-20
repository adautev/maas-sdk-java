package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
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

/**
 * Main class for interfacing with Miracl service.
 */
public class MiraclClient
{
	private static final String KEY_STATE = "miracl_state";
	private static final String KEY_NONCE = "miracl_nonce";
	private static final String KEY_TOKEN = "miracl_token";
	private static final String KEY_USERINFO = "miracl_userinfo";

	private final ClientID clientId;
	private final Secret clientSecret;
	private final URI redirectUrl;
	private final OIDCProviderMetadata providerMetadata;

	/**
	 * @param clientId     Client ID
	 * @param clientSecret Client secret
	 * @param redirectUrl  Redirect URL
	 * @throws MiraclException if parameters can't be parsed
	 */
	public MiraclClient(String clientId, String clientSecret, String redirectUrl) throws MiraclException
	{
		this(clientId, clientSecret, redirectUrl, MiraclConfig.ISSUER);
	}

	/**
	 * @param clientId     Client ID
	 * @param clientSecret Client secret
	 * @param redirectUrl  Redirect URL
	 * @param issuer       Issuer URL
	 * @throws MiraclException if parameters can't be parsed
	 */
	public MiraclClient(String clientId, String clientSecret, String redirectUrl, String issuer) throws MiraclException
	{
		try
		{
			this.clientId = new ClientID(clientId);
			this.clientSecret = new Secret(clientSecret);
			this.redirectUrl = new URI(redirectUrl);
			try
			{
				URI issuerURI = new URI(issuer);
				URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration").toURL();
				InputStream stream = providerConfigurationURL.openStream();

				String providerInfo = null;
				try (java.util.Scanner s = new java.util.Scanner(stream))
				{
					providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
				}
				providerMetadata = OIDCProviderMetadata.parse(providerInfo);

			}
			catch (IOException e)
			{
				throw new MiraclSystemException(e);
			}

		}
		catch (URISyntaxException | ParseException e)
		{
			throw new MiraclSystemException(e);
		}
	}

	/**
	 * Get {@link URI} for authorization request. URL should be used with mpin.js login function
	 * mpin.login({authURL: "< auth-url >"}). After user is redirected back (to redirect URL defined in constructor),
	 * call {@link #validateAuthorization(MiraclStatePreserver, String)} to complete authorization with server.
	 *
	 * @param preserver Miracl preserver object for current user
	 * @return Request URI for mpin authorization. After request redirects back, pass queryString
	 * to {@link #validateAuthorization(MiraclStatePreserver, String)} to complete authorization with server.
	 */
	public URI getAuthorizationRequestUrl(MiraclStatePreserver preserver)
	{
		State state = new State();
		Nonce nonce = new Nonce();
		preserver.put(KEY_STATE, state.getValue());
		preserver.put(KEY_NONCE, nonce.getValue());

		Scope scope = new Scope();
		scope.add("openid");
		scope.add("sub");
		scope.add("email");


		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
				providerMetadata.getAuthorizationEndpointURI(),
				new ResponseType(ResponseType.Value.CODE),
				scope, clientId, redirectUrl, state, nonce);

		return authenticationRequest.toURI();
	}

	/**
	 * Completes authorization with server and returns access token. Access token is saved in
	 * {@link MiraclStatePreserver preserver} so usually it is not needed to save access token
	 * This method can block while performing request to Miracl system
	 *
	 * @param preserver   Miracl preserver object for current user
	 * @param queryString query string from request on redirectUrl
	 * @return Token
	 * @throws MiraclClientException if there is problem with token request
	 * @throws MiraclSystemException if failure occurred while communicating with server
	 */
	public String validateAuthorization(MiraclStatePreserver preserver, String queryString) throws MiraclException
	{
		try
		{
			final AuthenticationResponse response;
			try
			{
				response = AuthenticationResponseParser.parse(URI.create("/?" + queryString));
			}
			catch (ParseException e)
			{
				throw new MiraclClientException(e);
			}
			if (response instanceof AuthenticationErrorResponse)
			{
				ErrorObject error = ((AuthenticationErrorResponse) response).getErrorObject();
				throw new Error(error.getDescription());
			}

			AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;

			final boolean stateOk = successResponse.getState().toString().equals(preserver.get(KEY_STATE));
			if (stateOk)
			{
				final String accessToken = requestAccessToken(((AuthenticationSuccessResponse) response).getAuthorizationCode());
				preserver.put(KEY_TOKEN, accessToken);
				return accessToken;
			}
		}
		catch (ParseException | IOException | Error e)
		{
			e.printStackTrace();
			throw new MiraclSystemException(e);
		}

		return null;
	}

	protected String requestAccessToken(AuthorizationCode authorizationCode) throws IOException, ParseException
	{
		TokenRequest tokenRequest = new TokenRequest(
				providerMetadata.getTokenEndpointURI(),
				new ClientSecretBasic(clientId, clientSecret),
				new AuthorizationCodeGrant(authorizationCode, redirectUrl)
		);
		final TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
		if (tokenResponse instanceof TokenErrorResponse)
		{
			ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
			throw new MiraclClientException(error);
		}

		OIDCTokenResponse accessTokenResponse = (OIDCTokenResponse) tokenResponse;
		final AccessToken accessToken = accessTokenResponse.getOIDCTokens().getAccessToken();
		return accessToken.getValue();
	}


	/**
	 * Clears user info from {@link MiraclStatePreserver preserver}. Can be used to refresh user data before using
	 * {@link #getUserId(MiraclStatePreserver)} and {@link #getEmail(MiraclStatePreserver)}
	 *
	 * @param preserver Miracl preserver object for current user
	 * @see #clearUserInfoAndSession(MiraclStatePreserver) to remove session info
	 */
	public void clearUserInfo(MiraclStatePreserver preserver)
	{
		preserver.remove(KEY_USERINFO);
	}

	/**
	 * Clears user and session info from {@link MiraclStatePreserver preserver}
	 *
	 * @param preserver Miracl preserver object for current user
	 * @see #clearUserInfo(MiraclStatePreserver) to remove only user info
	 */
	public void clearUserInfoAndSession(MiraclStatePreserver preserver)
	{
		clearUserInfo(preserver);
		preserver.remove(KEY_TOKEN);
	}

	private UserInfo getUserInfo(MiraclStatePreserver preserver) throws MiraclException
	{
		if (preserver.get(KEY_TOKEN) == null)
		{
			throw new MiraclClientException("User is not authorized");
		}

		if (preserver.get(KEY_USERINFO) != null)
		{
			final UserInfo userInfo;
			try
			{
				userInfo = UserInfo.parse(preserver.get(KEY_USERINFO));
				return userInfo;
			}
			catch (ParseException e)
			{
				//If problems with userinfo parsing, remove it and continue with obtaining new userinfo
				preserver.remove(KEY_USERINFO);
			}
		}


		try
		{
			UserInfo userInfo = requestUserInfo(preserver.get(KEY_TOKEN));
			preserver.put(KEY_USERINFO, userInfo.toJSONObject().toJSONString());
			return userInfo;

		}
		catch (SerializeException | IOException | ParseException e)
		{
			throw new MiraclSystemException(e);
		}
	}

	protected UserInfo requestUserInfo(String token) throws IOException, ParseException
	{
		final BearerAccessToken accessToken = new BearerAccessToken(token);
		UserInfoRequest userInfoReq = new UserInfoRequest(
				providerMetadata.getUserInfoEndpointURI(),
				accessToken);

		HTTPResponse userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
		UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);

		if (userInfoResponse instanceof UserInfoErrorResponse)
		{
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
			throw new MiraclClientException(error);
		}

		UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponse;
		return successResponse.getUserInfo();
	}

	/**
	 * Checks if token is in {@link MiraclStatePreserver preserver} and user data is accessible (by request or in cache).
	 * This method can block while performing request to Miracl system
	 *
	 * @param preserver Miracl preserver object for current user
	 * @return if user associated with {@link MiraclStatePreserver preserver} is authorized
	 */
	public boolean isAuthorized(MiraclStatePreserver preserver)
	{
		try
		{
			return getUserInfo(preserver) != null;
		}
		catch (MiraclClientException e)
		{
			return false;
		}
	}

	/**
	 * Get user e-mail.
	 * This method can block while performing request to Miracl system
	 *
	 * @param preserver Miracl preserver object for current user
	 * @return User e-mail
	 * @throws MiraclClientException if there is problem with request
	 * @throws MiraclSystemException if failure occurred while communicating with server
	 * @see #getUserId(MiraclStatePreserver) for requesting user ID
	 */
	public String getEmail(MiraclStatePreserver preserver) throws MiraclException
	{
		final UserInfo userInfo = getUserInfo(preserver);
		if (userInfo != null)
		{
			final String email = userInfo.getStringClaim("email");
			if (email != null)
			{
				return email;
			}
			else
			{
				return "";
			}

		}
		return null;
	}

	/**
	 * Get user id.
	 * This method can block while performing request to Miracl system
	 *
	 * @param preserver Miracl preserver object for current user
	 * @return User id
	 * @throws MiraclClientException if there is problem with request
	 * @throws MiraclSystemException if failure occurred while communicating with server
	 * @see #getEmail(MiraclStatePreserver) for requesting user e-mail
	 */
	public String getUserId(MiraclStatePreserver preserver) throws MiraclException
	{
		final UserInfo userInfo = getUserInfo(preserver);
		if (userInfo != null)
		{
			final String sub = userInfo.getStringClaim("sub");
			if (sub != null)
			{
				return sub;
			}
			else
			{
				return "";
			}
		}
		return null;
	}
}
