// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Session%20Fixation.md

HttpSession session = request.getSession();
String sessionId = UUID.randomUUID().toString();

session.setId(sessionId);

Cookie cookie = new Cookie("sessionId", sessionId);
cookie.setHttpOnly(true);
cookie.setSecure(true);
response.addCookie(cookie);
