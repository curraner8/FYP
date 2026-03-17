import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/CORS%20Misconfiguration.md

public class VulnerableServlet extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // This is a vulnerable code snippet with no CORS configuration
        response.setHeader("Access-Control-Allow-Origin", "*"); // Allow any origin (Not recommended)
        response.getWriter().write("This is a vulnerable resource.");
    }
}
