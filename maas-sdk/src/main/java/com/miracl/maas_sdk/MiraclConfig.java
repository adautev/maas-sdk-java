package com.miracl.maas_sdk;

final class MiraclConfig {
    static final String PLUGGABLE_VERIFICATION_PULL_ENDPOINT = "/activate/pull";
    static final String DEFAULT_ISSUER = "https://api.mpin.io";
    static final String CERTS_API_ENDPOINT = "/oidc/certs";
    static final String PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT = "/activate/user";
    static final String OPENID_CONFIG_ENDPOINT = "/.well-known/openid-configuration";

    public static String ISSUER = DEFAULT_ISSUER;
    public static void setIssuer(String issuer) {
        ISSUER = issuer;
    }
}
