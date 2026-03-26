import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/HSTS%20not%20Implemented.md

public class NoHSTSSecure extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // Secure code: The application sets an HSTS header to enforce HTTPS for the specified duration
        response.setHeader("Strict-Transport-Security", "max-age=31536000");

        // Generate response
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println(
            "This page sets an HTTP Strict Transport Security header to enforce HTTPS for 1 year."
        );
        out.println("</body></html>");
    }
}
