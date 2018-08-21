package com.miracl.maas_sdk;

final class MiraclConfig {
    private MiraclConfig() {

    }
    public static final String PLUGGABLE_VERIFICATION_PULL_ENDPOINT = "/activate/pull";
    public static final String DEFAULT_ISSUER = "https://api.mpin.io";
    public static String ISSUER = DEFAULT_ISSUER;
    public static final String CERTS_API_ENDPOINT = "/oidc/certs";
    public static final String PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT = "/activate/user";
    public static final String OPENID_CONFIG_ENDPOINT = "/.well-known/openid-configuration";
    public static void setIssuer(String issuer) {
        ISSUER = issuer;
    }
}
