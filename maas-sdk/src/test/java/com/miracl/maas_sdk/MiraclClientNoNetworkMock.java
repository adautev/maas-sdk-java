package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import org.testng.Assert;

import java.io.IOException;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

public class MiraclClientNoNetworkMock extends MiraclClient
{
	public MiraclClientNoNetworkMock(String clientId, String clientSecret, String redirectUrl) throws MiraclException
	{
		super(clientId, clientSecret, redirectUrl);
	}

	public MiraclClientNoNetworkMock(String clientId, String clientSecret, String redirectUrl, String issuer) throws MiraclException
	{
		super(clientId, clientSecret, redirectUrl, issuer);
	}


	@Override
	protected String requestAccessToken(AuthorizationCode authorizationCode) throws IOException, ParseException
	{
		Assert.assertEquals(authorizationCode.getValue(), "MOCK_CODE");
		return "MOCK_TOKEN";
	}

	@Override
	protected UserInfo requestUserInfo(String token) throws IOException, ParseException
	{
		Assert.assertEquals("MOCK_TOKEN", token);
		UserInfo userInfo = new UserInfo(new Subject("MOCK_USER"));
		try
		{
			userInfo.setEmail(new InternetAddress("mock@user.none"));
		}
		catch (AddressException ignored)
		{

		}
		return super.requestUserInfo(token);
	}
}
