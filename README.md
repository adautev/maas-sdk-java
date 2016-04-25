# Setup

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

## Local Installation

Use `./gradlew maas-sdk:publishToMavenLocal` to compile SDK and install it as artifact to local Maven repository.
`maas-sdk` directory can also be used as subproject in Gradle project.

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

If user is not authorized, he should be redirected to URL returned by
`client.getAuthorizationRequestUrl(session)`. After redirect and user
interaction with Miracl system, user will be sent to `redirectUri` defined at
creation of `MiraclClient` object.

To complete authorization pass query string received on `redirectUri` to
`client.validateAuthorization(session,query_string)`. This method will return
token if authorization succeeded. Token is preserved in `session` so there 
is no need to save token elsewhere.

### Problems and exceptions

Each call to `MiraclClient` can raise `MiraclException`. `MiraclException` can be

* `MiraclClientException` - for recoverable exceptions, for example - user denied authorization.
* `MiraclSystemException` - for exceptions that shouldn't happen in normal situation - parse errors, network errors etc.

## Samples

Replace `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI` with valid data from
https://m-pin.my.id/protected . Samples can be run after setup step is done.
