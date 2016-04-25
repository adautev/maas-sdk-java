package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class MiraclSystemException extends MiraclException
{
	public MiraclSystemException(String message)
	{
		super(message);
	}

	public MiraclSystemException(Exception e)
	{
		super(e);
	}

	public MiraclSystemException(ErrorObject e)
	{
		super(e);
	}
}
