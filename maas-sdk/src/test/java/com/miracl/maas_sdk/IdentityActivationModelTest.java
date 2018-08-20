package com.miracl.maas_sdk;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class IdentityActivationModelTest {

    private IdentityActivationModel modelInstance;

    @BeforeClass
    public void setUp()  {
        modelInstance = new IdentityActivationModel("mpinIdHash", "activateKey", "subject" );
    }
    @Test
    public void testGetМPinIdHash() {
        assertEquals(modelInstance.getМPinIdHash(), "mpinIdHash");
    }

    @Test
    public void testGetActivationKey() {
        assertEquals(modelInstance.getActivationKey(), "activateKey");
    }

    @Test
    public void testGetSubject() {
        assertEquals(modelInstance.getSubject(), "subject");
    }
}