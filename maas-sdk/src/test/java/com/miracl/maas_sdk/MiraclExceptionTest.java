package com.miracl.maas_sdk;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class MiraclExceptionTest {

	@Test
	public void testSystemExceptionFromString() throws Exception {
		MiraclException e = new MiraclSystemException("test");
		Assert.assertEquals(e.getMessage(), "test");
	}

	@Test
	public void testSystemExceptionFromThrowable() throws Exception {
		Exception e = new RuntimeException("test");
		MiraclException me = new MiraclSystemException(e);
		Assert.assertEquals(me.getMessage(),  "java.lang.RuntimeException: test");
	}

	@Test
	public void testSystemExceptionFromError() throws Exception {
		ErrorObject e = new ErrorObject("test");
		MiraclException me = new MiraclSystemException(e);
		Assert.assertEquals(me.getMessage(), "Network error: test null");
	}
	
	@Test
	public void testSystemExceptionFromNullError() throws Exception {
		ErrorObject e = null;
		MiraclException me = new MiraclSystemException(e);
		Assert.assertEquals(me.getMessage(), "Network error: <null>");		
	}

	@Test
	public void testClientExceptionFromString() throws Exception {
		MiraclException e = new MiraclClientException("test");
		Assert.assertEquals(e.getMessage(), "test");
	}
	
	@Test
	public void testClientExceptionFromThrowable() throws Exception {
		Exception e = new RuntimeException("test");
		MiraclException me = new MiraclClientException(e);
		Assert.assertEquals(me.getMessage(),  "java.lang.RuntimeException: test");
	}

	@Test
	public void testClientExceptionFromError() throws Exception {
		ErrorObject e = new ErrorObject("test");
		MiraclException me = new MiraclClientException(e);
		Assert.assertEquals(me.getMessage(), "Network error: test null");
	}
	
}
