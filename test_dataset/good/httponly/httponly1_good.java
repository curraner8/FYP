// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/HttpOnly%20Flag%20not%20set.md

Cookie cookie = new Cookie("sessionToken", sessionTokenValue);
cookie.setHttpOnly(true);
response.addCookie(cookie);
