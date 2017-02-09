package com.miracl.maas_sdk;

/**
 * Universal map-like string key-value store interface for abstracting Miracl
 * client data storage. Implementation of this interface is framework-specific
 * and it usually is wrapper around secure cookie storage or session storage.
 *
 * @see MiraclMapStatePreserver for example implementation using Map
 */
public interface MiraclStatePreserver {
	/**
	 * Get value for key
	 * 
	 * @param key
	 *            Key
	 * @return value for that key or null
	 */
	String get(String key);

	/**
	 * Put value in preserver. If key already exist in preserver, overwrite it's
	 * value.
	 * 
	 * @param key
	 *            Key
	 * @param value
	 *            Value
	 */
	void put(String key, String value);

	/**
	 * Remove key from preserver.
	 * 
	 * @param key
	 *            Key
	 */
	void remove(String key);
}
