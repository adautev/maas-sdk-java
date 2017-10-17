# maas-sdk-java

[![Master Build Status](https://secure.travis-ci.org/miracl/maas-sdk-java.png?branch=master)](https://travis-ci.org/miracl/maas-sdk-java?branch=master)
[![Master Coverage Status](https://coveralls.io/repos/github/miracl/maas-sdk-java/badge.svg?branch=master)](https://coveralls.io/github/miracl/maas-sdk-java?branch=master)

* **category**:    SDK
* **copyright**:   2017 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/maas-sdk-java

## Description

Java version of the Software Development Kit (SDK) for MPin-As-A-Service (MAAS).


## Setup

Current sdk version is `0.1-SNAPSHOT`. Replace `VERSION` with needed version in examples.

To use `maas-sdk` with Maven project, use:
```
<dependency>
  <groupId>com.miracl</groupId>
  <artifactId>maas-sdk</artifactId>
  <version>VERSION</version>
</dependency>
```

For Gradle project:
```
dependencies {
    compile 'com.miracl:maas-sdk:VERSION'
}
```

`maas-sdk` needs Java 8.

All commands in this document are for Linux/MacOS. For Windows command, replace `./gradlew` with `gradlew.bat`.

## Local Installation

Use `./gradlew maas-sdk:publishToMavenLocal` to compile SDK and install it as artifact to local Maven repository.
`maas-sdk` directory can also be used as subproject in Gradle project.

## Documentation generation

To generate JavaDoc, use `./gradlew maas-sdk:javadoc`. Result can be found in `maas-sdk/build/docs`.

# Miracl API

## Details and usage

All interaction with API happens through `MiraclClient` object. Each
application needs to construct instance of `MiraclClient`.

Miracl API requires map-like object for storing state and additional data (it
should be preserved between calls to api). Object should implement `MiraclStatePreserver`.
`session` in this document is instance of `MiraclStatePreserver`.

### Initialization
To start using Miracl API, `MiraclClient` should be initialized. It can be done
when needed or at application startup. This instance can be shared between
threads and is thread-safe. `client` in this document is instance of `MiraclClient`.

### Status check and user data

To check if user session is authorized use `client.isAuthorized(session)`. You can
 request additional user data with `client.getEmail(session)` and
 `client.getUserId(session)`. Both methods cache results into `session`.

Use `client.clearUserInfo(session)` to drop cached user data (e-mail and
user id), use `client.clearUserInfoAndSession(session)` to also clear user authorization status.

### Authorization flow

Authorization flow depends on `mpad.js` browser library. To show login button:

* Put div with distinct ID where login button should be
* Create authorization URL by using `client.getAuthorizationRequestUrl(session)`
* At the end of page body load `mpad.js` with parameters `data-authurl`
(authorization URL) and `data-element` (login button ID)

```
<script src="<<Insert correct mpad url here>>" data-authurl="{{ auth_url }}" data-element="btmpin"></script>
```

Please refer to your distributor-specific documentation to find the correct url for the mpad.js `script src`

After user interaction with Miracl system, user will be sent to `redirectUri` defined at
creation of `MiraclClient` object.

To complete authorization pass query string received on `redirectUri` to
`client.validateAuthorization(session,query_string)`. This method will return
token if authorization succeeded. Token is preserved in `session` so there
is no need to save token elsewhere.

### Proxy server support

A proxy server can be used by calling the `useProxy(host, port)` method found in `MiraclClient`.
Proxy support is handled by the standard [Java Networking API](https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html).
You can consult the included code samples to see how proxy server configuration can be passed into your application.

### Problems and exceptions

Each call to `MiraclClient` can raise `MiraclException`. `MiraclException` can be

* `MiraclClientException` - for recoverable exceptions, for example - user denied authorization.
* `MiraclSystemException` - for exceptions that shouldn't happen in normal situation - parse errors, network errors etc.

## Samples


Configuration is located in `miracl.json`.

Replace `CLIENT_ID`, `SECRET` and `REDIRECT_URI` with valid data from
Miracl. Samples can be run after setup step is done.

Redirect URI for this sample is `http://127.0.0.1:5000/login` if run locally.

To run Spark sample, use `./gradlew sample-spark:run`

## Docker

Configure the sample app (see above) then run docker

`docker build --tag=miracl/javasdk:latest .`

`docker run -it -p 5000:5000 miracl/javasdk`

Open the app at url `http://127.0.0.1:5000/` 
