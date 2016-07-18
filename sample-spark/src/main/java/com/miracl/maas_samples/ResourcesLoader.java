package com.miracl.maas_samples;

import com.mitchellbosecke.pebble.error.LoaderException;
import com.mitchellbosecke.pebble.loader.Loader;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;

/**
 * Resource loader for reading template from resources
 */
public class ResourcesLoader implements Loader
{
	private String charset = "UTF-8";
	private String prefix = "";
	private String suffix = "";

	@Override
	public Reader getReader(String templateName) throws LoaderException
	{
		try
		{
			final String name = prefix + templateName + suffix;
			final InputStream resourceAsStream = ResourcesLoader.class.getClassLoader().getResourceAsStream(name);
			return new InputStreamReader(resourceAsStream, charset);
		}
		catch (UnsupportedEncodingException e)
		{
			throw new LoaderException(e, "Template reader was not created");
		}
	}

	@Override
	public void setCharset(String charset)
	{

		this.charset = charset;
	}

	@Override
	public void setPrefix(String prefix)
	{

		this.prefix = prefix;
	}

	@Override
	public void setSuffix(String suffix)
	{

		this.suffix = suffix;
	}
}
