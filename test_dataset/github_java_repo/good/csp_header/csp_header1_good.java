import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Missing%20CSP%20Header.md

public class NoCSPSecure extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // Secure code: The application sets a default-src CSP header to block all untrusted sources
        response.setHeader("Content-Security-Policy", "default-src 'none'");

        // Generate response
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println(
            "This page sets a Content-Security-Policy header to block all untrusted sources."
        );
        out.println("</body></html>");
    }
}
