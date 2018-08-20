package com.miracl.maas_sdk;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.HashMap;

import static org.testng.Assert.*;

public class MiraclMapStatePreserverTest {

    private MiraclMapStatePreserver statePreserverInstance;

    @BeforeClass
    public void setUp() {
        statePreserverInstance = new MiraclMapStatePreserver(new HashMap<>());
        statePreserverInstance.put("sampleGetKey", "sampleGetValue");
        statePreserverInstance.put("samplePutKey", "samplePutValue");
        statePreserverInstance.put("sampleRemoveKey", "sampleRemoveValue");
    }
    @Test
    public void testGet() {
        assertEquals("sampleGetValue", statePreserverInstance.get("sampleGetKey"));
    }

    @Test
    public void testPut() {
        statePreserverInstance.put("samplePutKey", "samplePutChangedValue");
        assertEquals("samplePutChangedValue", statePreserverInstance.get("samplePutKey"));
    }

    @Test
    public void testRemove() {
        statePreserverInstance.remove("sampleRemoveKey");
        assertNull(statePreserverInstance.get("sampleRemoveKey"));
    }
}