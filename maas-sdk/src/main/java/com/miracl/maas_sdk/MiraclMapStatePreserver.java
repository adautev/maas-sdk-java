package com.miracl.maas_sdk;

import java.util.Map;

/**
 * Preserver implementation that wraps {@link Map} instance.
 */
public class MiraclMapStatePreserver implements MiraclStatePreserver
{
	private final Map<String, String> map;

	/**
	 * @param map Modifiable map that will be used as storage
	 */
	public MiraclMapStatePreserver(Map<String, String> map)
	{
		this.map = map;
	}

	/**
	 * @see MiraclStatePreserver#get(String)
	 */
	@Override
	public String get(String key)
	{
		return map.get(key);
	}

	/**
	 * @see MiraclStatePreserver#put(String, String)
	 */
	@Override
	public void put(String key, String value)
	{
		map.put(key, value);
	}

	/**
	 * @see MiraclStatePreserver#remove(String)
	 */
	@Override
	public void remove(String key)
	{
		map.remove(key);
	}
}
