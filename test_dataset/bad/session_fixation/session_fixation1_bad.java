// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Session%20Fixation.md

HttpSession session = request.getSession();
String sessionId = request.getParameter("sessionId");

if (sessionId != null) {
session.setId(sessionId);
}
