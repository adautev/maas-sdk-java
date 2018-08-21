package com.miracl.maas_sdk;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class MiraclConfigTest {

    @Test
    public void testSetIssuer() {
        MiraclConfig.setIssuer("testIssuer");
        assertEquals("testIssuer", MiraclConfig.ISSUER);
    }

    @Test
    public void testConstructor() {
        assertNotNull(new MiraclConfig());
    }

    @Test
    public void testCertsApiEndpoint() {
        assertEquals("/oidc/certs", MiraclConfig.CERTS_API_ENDPOINT);
    }

    @Test
    public void testPVPullEndpoint() {
        assertEquals("/activate/pull", MiraclConfig.PLUGGABLE_VERIFICATION_PULL_ENDPOINT);
    }

    @Test
    public void testPVActivationEndpoint() {
        assertEquals("/activate/user", MiraclConfig.PLUGGABLE_VERIFICATION_ACTIVATION_ENDPOINT);
    }

    @Test
    public void testOIDConfigEndpoint() {
        assertEquals("/.well-known/openid-configuration", MiraclConfig.OPENID_CONFIG_ENDPOINT);
    }
}
