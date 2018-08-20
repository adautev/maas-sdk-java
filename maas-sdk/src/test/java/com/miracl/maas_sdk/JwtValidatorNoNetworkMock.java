package com.miracl.maas_sdk;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class JwtValidatorNoNetworkMock extends JwtValidator {
	
	public JwtValidatorNoNetworkMock(String algorithm) {
		super(algorithm);
	}

	public JwtValidatorNoNetworkMock(JWSAlgorithm algorithm, String url) {
		super(algorithm, url);
	}

	public JwtValidatorNoNetworkMock(JWSAlgorithm algorithm, URL url) {
		super(algorithm, url);
	}

	public JwtValidatorNoNetworkMock(JWSAlgorithm algorithm) {
		super(algorithm);
	}

	@Override
	public ConfigurableJWTProcessor<SecurityContext> buildJwtProcessor(JWSAlgorithm algorithm) {
		ConfigurableJWTProcessor<SecurityContext> processor;
		JWKSource<SecurityContext> keySource;
		JWKSet keySet;
		JWSKeySelector<SecurityContext> keySelector;

		File file = new File(getClass().getClassLoader().getResource("jwk.json").getFile());

		try {
			processor = new DefaultJWTProcessor<>();
			keySet = JWKSet.load(file);
			keySource = new ImmutableJWKSet<>(keySet);
			keySelector = new JWSVerificationKeySelector<>(algorithm, keySource);
			processor.setJWSKeySelector(keySelector);

			return processor;
		} catch (IOException | java.text.ParseException e) {
			return null;
		}
	}


}
