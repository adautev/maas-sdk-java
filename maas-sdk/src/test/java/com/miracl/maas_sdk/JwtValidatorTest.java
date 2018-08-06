package com.miracl.maas_sdk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.text.ParseException;
import java.util.Properties;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;

public class JwtValidatorTest {

	Properties properties;
	JwtValidator validator;

	@BeforeClass
	public void setUpClass() throws Exception {
		properties = new Properties();
		try (InputStream in = getClass().getClassLoader().getResourceAsStream("test.properties")) {
			properties.load(in);
		}
	}

	@Test
	public void testValidateNonJsonToken() {
		validator = new JwtValidator("RS256");
		Assert.assertFalse(validator.validateToken(""));
	}

	@Test
	public void testBuildJwtProcessorBadUrl() {
		try {
			validator = new JwtValidator(JWSAlgorithm.HS256, "bad URL");
			validator.buildJwtProcessor(JWSAlgorithm.RS256);
		} catch (MiraclClientException e) {
			Assert.assertTrue(e.getMessage().contains("bad URL"));
			return;
		}

		Assert.fail("It was possible to build a JWT processor with an invalid URL");
	}

	@Test
	public void testBuildJwtProcessor() throws Exception {
		URL url = createMockHttpUrl("jwk.json");

		ConfigurableJWTProcessor<SecurityContext> processor;
		validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256, url);
		processor = validator.buildJwtProcessor(JWSAlgorithm.HS256);

		try {
			JWTClaimsSet claims = processor.process(properties.getProperty("jwt.valid"), null);
			Assert.assertEquals(claims.getClaim("Email"), "test2@miracl.com");
		} catch (ParseException | BadJOSEException | JOSEException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testExtractClaims() throws Exception {
		validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256);
		JWTClaimsSet claims = validator.extractClaims(properties.getProperty("jwt.valid"));
		Assert.assertEquals(claims.getSubject(), "test@miracl.com");
	}

	@Test
	public void testValidateToken() {
		// Validation should pass for this one
		try {
			validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256);
			validator.validateToken(properties.getProperty("jwt.valid"));
		} catch (MiraclSystemException e) {
			Assert.fail("JWT signature validation failed for a valid signature #1: " + e.getMessage());
		}

		// Validation should pass for this one
		try {
			validator = new JwtValidatorNoNetworkMock("HS256");
			validator.validateToken(properties.getProperty("jwt.valid"));
		} catch (MiraclSystemException e) {
			Assert.fail("JWT signature validation failed for a valid signature #2: " + e.getMessage());
		}

		// Validation should fail for this one
		try {
			validator = new JwtValidatorNoNetworkMock(JWSAlgorithm.HS256);
			Assert.assertFalse(validator.validateToken(properties.getProperty("jwt.invalidSignature")));
		} catch (MiraclSystemException e) {
			Assert.assertTrue(e.getMessage().contains("Invalid signature"));
			return;
		}

	}

	@Test
	public void testGetJWSAlgorithm() throws Exception {
		Assert.assertEquals(JwtValidator.getJWSAlgorithm("HS256"), JWSAlgorithm.HS256);
	}

	/**
	 * Create a mock HTTP URL for testing functionality that requires such.
	 * 
	 * @param filename
	 *            A filename, stored in test/resources, to use for source
	 * @return
	 * @throws Exception
	 */
	protected URL createMockHttpUrl(String filename) throws Exception {
		URLConnection mockConnection = new MockURLConnection(filename);
		URLStreamHandler handler = new URLStreamHandler() {
			@Override
			protected URLConnection openConnection(final URL arg0) throws IOException {
				return mockConnection;
			}
		};
		return new URL("http", "example.com", 80, "", handler);
	}
}
