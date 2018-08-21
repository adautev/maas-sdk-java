package com.miracl.maas_sdk;

import org.testng.Assert;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class MiraclMessagesTest {
    @Test
    public void testMiraclMessages() {
        Assert.assertNotNull(new MiraclMessages());
    }
}