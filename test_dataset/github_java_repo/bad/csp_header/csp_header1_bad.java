import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Missing%20CSP%20Header.md

public class NoCSPVulnerable extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // Generate response
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("This page does not set a Content-Security-Policy header.");
        out.println("</body></html>");
    }
}
