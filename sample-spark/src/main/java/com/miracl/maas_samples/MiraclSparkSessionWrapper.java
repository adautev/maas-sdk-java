package com.miracl.maas_samples;

import com.miracl.maas_sdk.MiraclStatePreserver;

import spark.Session;

/**
 * Session wrapper that uses Spark {@link Session} for preserving data
 */
public class MiraclSparkSessionWrapper implements MiraclStatePreserver
{
	private final Session session;

	public MiraclSparkSessionWrapper(Session session)
	{
		this.session = session;
	}

	@Override
	public String get(String key)
	{
		return session.attribute(key);
	}

	@Override
	public void put(String key, String value)
	{
		session.attribute(key, value);
	}

	@Override
	public void remove(String key)
	{
		session.removeAttribute(key);
	}


}
