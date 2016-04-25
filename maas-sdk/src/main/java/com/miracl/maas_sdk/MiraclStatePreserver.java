package com.miracl.maas_sdk;

public interface MiraclStatePreserver
{
	String get(String key);
	void put(String key, String value);
	void remove(String key);
}
