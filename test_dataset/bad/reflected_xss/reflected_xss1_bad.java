// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Reflected%20Cross-Site-Scripting%20(XSS).md

String searchTerm = request.getParameter("term");
out.println("<h1>Search Results for: " + searchTerm + "</h1>");
