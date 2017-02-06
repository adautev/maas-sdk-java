package com.miracl.maas_sdk;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Exception thrown when problem occurred with Miracl system or communication
 * with it (error while parsing response, networking error etc.). It's best to
 * present user with error response when this exception occurs.
 */
public class MiraclSystemException extends MiraclException {
	private static final long serialVersionUID = 4422618452441970337L;

	public MiraclSystemException(String message) {
		super(message);
	}

	public MiraclSystemException(Throwable e) {
		super(e);
	}

	public MiraclSystemException(ErrorObject e) {
		super(e);
	}
}
