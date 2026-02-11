import java.net.MalformedURLException;
import java.net.URL;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Open%20Redirection.md

String redirectUrl = request.getParameter("url");
try {
URL url = new URL(redirectUrl);
String host = url.getHost();
if (host.equals("example.com") || host.endsWith(".example.com")) {
response.sendRedirect(redirectUrl);
} else {
response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect URL");
}
} catch (MalformedURLException e) {
response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid redirect URL");
}
