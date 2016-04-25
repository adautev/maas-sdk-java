package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class MiraclClientException extends MiraclException
{
	public MiraclClientException(String message)
	{
		super(message);
	}

	public MiraclClientException(Exception e)
	{
		super(e);
	}

	public MiraclClientException(ErrorObject e)
	{
		super(e);
	}
}
