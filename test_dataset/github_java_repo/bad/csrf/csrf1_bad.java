import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Cross-Site%20Request%20Forgery%20(CSRF).md

public class CSRFVulnerable extends HttpServlet {

    protected void doPost(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
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
