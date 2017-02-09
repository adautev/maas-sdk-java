package com.miracl.maas_sdk;

import java.net.MalformedURLException;
import java.net.URL;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Tools related to JWT signature validation and working with claims.
 *
 */
public class JwtValidator {

	JWSAlgorithm algorithm;
	URL keySourceUrl;

	public JwtValidator(JWSAlgorithm algorithm, URL keySourceUrl) {
		this.algorithm = algorithm;
		this.keySourceUrl = keySourceUrl;
	}

	public JwtValidator(JWSAlgorithm algorithm, String keySourceUrl) {
		this.algorithm = algorithm;

		try {
			this.keySourceUrl = new URL(keySourceUrl);
		} catch (MalformedURLException e) {
			throw new MiraclClientException(e);
		}
	}

	public JwtValidator(JWSAlgorithm algorithm) {
		this(algorithm, MiraclConfig.ISSUER + MiraclConfig.CERTS_API_ENDPOINT);
	}

	public JwtValidator(String algorithm) {
		this(getJWSAlgorithm(algorithm));
	}

	/**
	 * Create a JWT processor that can be used to verify tokens and extract
	 * claims.
	 * 
	 * @return A DefaultJWTProcessor
	 * @throws MiraclClientException
	 *             When the remote JWK URL is not valid
	 */
	public ConfigurableJWTProcessor<SecurityContext> buildJwtProcessor() {
		ConfigurableJWTProcessor<SecurityContext> processor;
		JWKSource<SecurityContext> keySource;
		JWSKeySelector<SecurityContext> keySelector;

		processor = new DefaultJWTProcessor<>();
		keySource = new RemoteJWKSet<>(keySourceUrl);
		keySelector = new JWSVerificationKeySelector<>(algorithm, keySource);
		processor.setJWSKeySelector(keySelector);

		return processor;
	}

	/**
	 * Extracts and returns a JWT's claims.
	 * 
	 * @param token
	 *            JSON Web Token to validate
	 * @return The JWT's claims
	 * @throws MiraclClientException
	 *             When the remote JWK URL is not valid
	 * @throws MiraclSystemException
	 *             When the token could not be validated
	 */
	public JWTClaimsSet extractClaims(String token) {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = buildJwtProcessor();

		try {
			return jwtProcessor.process(token, null);
		} catch (java.text.ParseException | BadJOSEException | JOSEException e) {
			throw new MiraclSystemException(e);
		}
	}

	/**
	 * Attempts to validate a JWT, throwing a MiraclSystemException if it
	 * cannot.
	 * 
	 * @param token
	 *            JSON Web Token to validate
	 * @throws MiraclClientException
	 *             When the remote JWK URL is not valid
	 * @throws MiraclSystemException
	 *             When the token could not be validated
	 */
	public void validateToken(String token) {
		extractClaims(token);
	}

	/**
	 * Get a JWSAlgorithm by its name.
	 * 
	 * @param name
	 * @return
	 */
	public static JWSAlgorithm getJWSAlgorithm(String name) {
		return new JWSAlgorithm(name);
	}
}
