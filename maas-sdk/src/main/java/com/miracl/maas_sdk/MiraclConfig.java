package com.miracl.maas_sdk;

class MiraclConfig {
    public static final String PLUGGABLE_VERIFICATION_PULL_ENDPOINT = "/activate/pull";
	public static final String ISSUER = "https://api.qa.miracl.net";
	public static final String CERTS_API_ENDPOINT = "/oidc/certs";
	public static final String PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT = "/activate/user";
	public  static final String OPENID_CONFIG_ENDPOINT = "/.well-known/openid-configuration";

	private MiraclConfig() {
	}
}
