package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Exception that is related to user data and Miracl system failure responses. Usually this exception mean that data
 * passed to MiraclClient (via parameters or {@link MiraclStatePreserver preserver}) are incorrect or in wrong state.
 */
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
