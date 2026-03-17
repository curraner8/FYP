// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Reflected%20Cross-Site-Scripting%20(XSS).md

import org.apache.commons.text.StringEscapeUtils;
...
String searchTerm = request.getParameter("term");
searchTerm = StringEscapeUtils.escapeHtml4(searchTerm);
out.println("<h1>Search Results for: " + searchTerm + "</h1>");
