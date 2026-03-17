import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Cross-Site%20Request%20Forgery%20(CSRF).md

public class CSRFSecure extends HttpServlet {

    protected void doPost(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // Check for a valid CSRF token
        String csrfToken = request.getParameter("csrf_token");
        if (
            !csrfToken.equals(request.getSession().getAttribute("csrf_token"))
        ) {
            response.sendError(
                HttpServletResponse.SC_FORBIDDEN,
                "Invalid CSRF token"
            );
            return;
        }

        // Read form data from request
        String newName = request.getParameter("new_name");

        // Get the logged-in user from the session
        User user = (User) request.getSession().getAttribute("user");
        if (user == null) {
            response.sendError(
                HttpServletResponse.SC_FORBIDDEN,
                "Not logged in"
            );
            return;
        }

        // Update the user's name
        user.setName(newName);
        updateUser(user);
    }
}
