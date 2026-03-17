// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Secure%20Cookie%20not%20set.md

String sessionToken = "abc123";
Cookie cookie = new Cookie("session_token", sessionToken);
cookie.setSecure(true);
response.addCookie(cookie);
