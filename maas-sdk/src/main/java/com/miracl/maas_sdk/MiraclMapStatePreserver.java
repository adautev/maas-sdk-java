package com.miracl.maas_sdk;

import java.util.Map;

public class MiraclMapStatePreserver implements MiraclStatePreserver
{
	private final Map<String, String> map;

	public MiraclMapStatePreserver(Map<String, String> map)
	{
		this.map = map;
	}

	@Override
	public String get(String key)
	{
		return map.get(key);
	}

	@Override
	public void put(String key, String value)
	{
		map.put(key, value);
	}

	@Override
	public void remove(String key)
	{
		map.remove(key);
	}
}
