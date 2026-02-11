// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Open%20Redirection.md

String redirectUrl = request.getParameter("url");
response.sendRedirect(redirectUrl);
