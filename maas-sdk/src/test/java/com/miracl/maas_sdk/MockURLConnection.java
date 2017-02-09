package com.miracl.maas_sdk;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Use for mocking HTTP connections in tests
 *
 */
class MockURLConnection extends HttpURLConnection {
	String filename;

	public MockURLConnection(String filename) throws MalformedURLException {
		super(new URL("http://example"));
		this.filename = filename;
	}

	@Override
	public void connect() throws IOException {
		// Do nothing
	}

	@Override
	public InputStream getInputStream() throws FileNotFoundException {
		File file = new File(getClass().getClassLoader().getResource(filename).getFile());
		return new FileInputStream(file);
	}

	@Override
	public void disconnect() {
		// Do nothing
		
	}

	@Override
	public boolean usingProxy() {
		return false;
	}
	
	@Override
	public int getResponseCode() {
		return 200;
	}
}
