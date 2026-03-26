import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Clickjacking.md

public class ClickjackingVulnerable extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // Generate response
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("This page is vulnerable to clickjacking attacks.");
        out.println("</body></html>");
    }
}
