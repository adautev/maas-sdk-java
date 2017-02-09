package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Base class for all Miracl exceptions.
 * 
 * @see MiraclClientException
 * @see MiraclSystemException
 */
public abstract class MiraclException extends RuntimeException {
	private static final long serialVersionUID = 25942225537564561L;

	public MiraclException(String message) {
		super(message);
	}

	public MiraclException(Throwable e) {
		super(e);
	}

	public MiraclException(ErrorObject e) {
		super(String.format(MiraclMessages.NETWORK_ERROR_EXCEPTION_DESC,
				e != null ? e.getCode() + " " + e.getDescription() : "<null>"));
	}
}
