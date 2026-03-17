import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/CORS%20Misconfiguration.md

public class SecureServlet extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // This is a secure code snippet with proper CORS configuration
        String allowedOrigin = "https://trusted-website.com";
        String origin = request.getHeader("Origin");

        if (allowedOrigin.equals(origin)) {
            response.setHeader("Access-Control-Allow-Origin", allowedOrigin);
            response.getWriter().write("This is a secure resource.");
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response
                .getWriter()
                .write(
                    "Access denied. This resource can only be accessed from a trusted origin."
                );
        }
    }
}
