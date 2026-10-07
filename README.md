# Spring Auth Server PKCE Challenge Validation Repro

Minimal reproduction of Spring Security Authorization Server accepting malformed PKCE `code_challenge` values at the authorization endpoint. It uses Spring Boot's default authorization server configuration and one PKCE-required client configured in `application.yaml`; there are no custom security filters or validators.

## Run

Requires Java 17 or later and Maven 3.9 or later. From the repository root, run:

```sh
mvn test
```

The test suite **intentionally fails** against Spring Security 7.1.1. Maven should report **1 passing test and 3 failing tests**. Test details are in `target/surefire-reports/`.

| Scenario | Expected authorization response | Observed with Spring Security 7.1.1 |
| --- | --- | --- |
| Valid S256 challenge, authenticated user | Redirect to the registered client callback with an authorization code | Code issued; test passes |
| Five-character S256 challenge, authenticated user | Redirect to the callback with `error=invalid_request` | Code issued; test fails |
| 43-character S256 challenge containing `!`, authenticated user | Redirect to the callback with `error=invalid_request` | Code issued; test fails |
| Five-character S256 challenge, anonymous browser request | Reject before login with `error=invalid_request` at the callback | Redirect to `/login`; test fails |

The authenticated tests supply a mock user through Spring Security test support, so no login form is submitted. The anonymous test sends an HTML browser request. All requests use a registered client and a valid registered callback; the assertions concern the **redirect destination and OAuth error**, not merely the HTTP status. The tests stop at authorization responses and do not exchange codes for tokens.

## Why these requests should fail

[RFC 7636 §4.2](https://datatracker.ietf.org/doc/html/rfc7636#section-4.2) defines `code-challenge = 43*128unreserved`, allowing letters, digits, `-`, `.`, `_`, and `~`. For S256, the challenge is the base64url encoding of a SHA-256 digest, which is 43 characters. The short and `!` challenges violate that syntax.

[RFC 6749 §4.1.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1) places authorization-request validation before user authentication. Its [authorization error rules in §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1) describe `invalid_request` for an invalid parameter value and returning errors through a valid client callback. RFC 7636 does not separately prescribe the response for a malformed challenge; the expected error here follows from those OAuth authorization-request rules together with the PKCE syntax.

Spring Security's [authorization server configuration documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/configuration-model.html) describes the default setup used here, and its [authorization endpoint documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/authorization-server/protocol-endpoints.html) describes request validation and error handling. The [7.1.1 challenge validator](https://github.com/spring-projects/spring-security/blob/7.1.1/oauth2/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/authentication/OAuth2AuthorizationCodeRequestAuthenticationValidator.java#L188-L208) checks for a nonblank challenge and S256 method, but not the challenge's length or allowed characters.

This project uses Spring Boot 4.1.1, which manages Spring Security 7.1.1. The issue demonstrated here is challenge syntax validation at authorization time; the tests do not demonstrate token issuance or a PKCE bypass.
