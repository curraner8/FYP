import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/HSTS%20not%20Implemented.md

public class NoHSTSVulnerable extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // Generate response
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("This is Sample Text");
        out.println("</body></html>");
    }
}
