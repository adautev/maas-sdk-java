package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Base class for all Miracl exceptions.
 * @see MiraclClientException
 * @see MiraclSystemException
 */
public abstract class MiraclException extends RuntimeException
{
	public MiraclException(String message)
	{
		super(message);
	}

	public MiraclException(Exception e)
	{
		super(e);
	}

	public MiraclException(ErrorObject e)
	{
		super("Network error: " + (e != null ? e.getCode() + " " + e.getDescription() : "<null>"));
	}
}
