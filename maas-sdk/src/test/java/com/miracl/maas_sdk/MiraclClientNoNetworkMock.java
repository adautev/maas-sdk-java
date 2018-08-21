package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;

import org.testng.Assert;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Collectors;

public class MiraclClientNoNetworkMock extends MiraclClient {
    private boolean erroneousActivationEndpointUrl;

    public MiraclClientNoNetworkMock(String clientId, String clientSecret, String redirectUrl) throws MiraclException {
        super(clientId, clientSecret, redirectUrl);
    }

    public MiraclClientNoNetworkMock(String clientId, String clientSecret, String redirectUrl, String issuer)
            throws MiraclException {
        super(clientId, clientSecret, redirectUrl, issuer);
    }

    @Override
    protected String getClientActivationEndpointURL() {
        if (erroneousActivationEndpointUrl) {
            return "dummy";
        }
        return super.getClientActivationEndpointURL();
    }

    @Override
    protected String requestProviderInfo(URL url) throws IOException {
        return "{\"acr_values_supported\":[\"0\"],\"subject_types_supported\":[\"public\"],\"request_parameter_supported\":false,\"userinfo_signing_alg_values_supported\":[\"HS256\",\"RS384\",\"HS512\",\"RS512\",\"RS256\",\"HS384\"],\"claims_supported\":[\"sub\",\"iss\",\"auth_time\",\"acr\",\"name\",\"given_name\",\"family_name\",\"nickname\",\"email\",\"email_verified\"],\"issuer\":\"https://api.dev.miracl.net\",\"ui_locales_supported\":[\"en\"],\"response_types_supported\":[\"code\",\"id_token\",\"token id_token\",\"code id_token\",\"token code id_token\"],\"require_request_uri_registration\":false,\"grant_types_supported\":[\"implicit\",\"authorization_code\",\"refresh_token\",\"password\",\"client_credentials\",\"urn:ietf:params:oauth:grant-type:jwt-bearer\"],\"token_endpoint\":\"https://api.dev.miracl.net/oidc/token\",\"display_values_supported\":[\"page\",\"popup\"],\"request_uri_parameter_supported\":false,\"response_modes_supported\":[\"query\",\"fragment\"],\"jwks_uri\":\"https://api.dev.miracl.net/oidc/certs\",\"scopes_supported\":[\"openid\",\"profile\",\"email\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"client_secret_basic\"],\"id_token_signing_alg_values_supported\":[\"RS256\",\"RS384\",\"RS512\"],\"claims_parameter_supported\":true,\"userinfo_endpoint\":\"https://api.dev.miracl.net/oidc/userinfo\",\"claim_types_supported\":[\"normal\"],\"authorization_endpoint\":\"https://api.dev.miracl.net/authorize\"}";
    }

    @Override
    protected String requestAccessToken(AuthorizationCode authorizationCode) throws IOException, ParseException {
        Assert.assertEquals(authorizationCode.getValue(), "MOCK_CODE");
        return "MOCK_TOKEN";
    }

    public void setErroneusGetClientActivationEndpointURL(boolean erroneous) {
        this.erroneousActivationEndpointUrl = erroneous;
    }

    @Override
    protected UserInfoResponse doUserInfoRequest(UserInfoRequest request) throws IOException, ParseException {
        URI uri;
        String jsonText;

        try {
            uri = getClass().getClassLoader().getResource("jwt.json").toURI();
        } catch (URISyntaxException e) {
            Assert.fail("Could not read jwt.json");
            return null;
        }

        jsonText = Files.lines(Paths.get(uri)).collect(Collectors.joining());
        JSONObject json = (JSONObject) JSONValue.parse(jsonText);

        return new UserInfoSuccessResponse(new UserInfo(json));
    }
}
