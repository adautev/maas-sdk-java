package com.miracl.maas_samples;

import com.miracl.maas_sdk.MiraclClient;

import static spark.Spark.get;

public class SparkSample
{


	public static void main(String[] args)
	{
		MiraclClient miracl = new MiraclClient("CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URL");
		get("/", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			if (miracl.isAuthorized(preserver))
			{
				return "Email: " + miracl.getEmail(preserver) + ", UserID: " + miracl.getUserId(preserver) +
				       " <a href='/refresh'>Refresh</a> <a href='/logout'>Logout</a>";
			}
			else
			{
				return "Not authorized. <a href='/auth'>Login</a>";
			}
		});

		get("/c2id", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			final String token = miracl.validateAuthorization(preserver, req.queryString());
			if (token != null)
			{
				res.redirect("/");
				return "";
			}
			else
			{
				return "Login failed! <a href='/auth'>Retry?</a>";
			}
		});

		get("/auth", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			res.redirect(miracl.getAuthorizationRequestUrl(preserver).toASCIIString());
			return "";
		});

		get("/refresh", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			miracl.clearUserInfo(preserver);
			res.redirect("/");
			return "";
		});

		get("/logout", (req, res) -> {
			final MiraclSparkSessionWrapper preserver = new MiraclSparkSessionWrapper(req.session());
			miracl.clearUserInfoAndSession(preserver);
			res.redirect("/");
			return "";
		});

	}
}
