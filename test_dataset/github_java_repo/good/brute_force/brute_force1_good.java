import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Brute%20Force.md

public class LoginSecure extends HttpServlet {

    protected void doPost(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        User user = authenticate(username, password);
        if (user != null) {
            // Login successful, set session attribute and redirect to dashboard
            request.getSession().setAttribute("user", user);
            response.sendRedirect("/dashboard");
        } else {
            // Login failed, increment failed login count in session and show error message
            Integer failedLoginCount = (Integer) request
                .getSession()
                .getAttribute("failed_login_count");
            if (failedLoginCount == null) {
                failedLoginCount = 0;
            }
            failedLoginCount++;
            request
                .getSession()
                .setAttribute("failed_login_count", failedLogincount);

            // Secure code: If the failed login count exceeds a threshold, log the user out for a specified duration
            if (failedLoginCount > 5) {
                request.getSession().setMaxInactiveInterval(1800); // 30 minutes
                request.setAttribute(
                    "errorMessage",
                    "Too many failed login attempts. You have been logged out for 30 minutes."
                );
                request
                    .getRequestDispatcher("/login.jsp")
                    .forward(request, response);
                return;
            }

            request.setAttribute(
                "errorMessage",
                "Invalid username or password"
            );
            request
                .getRequestDispatcher("/login.jsp")
                .forward(request, response);
        }
    }
}
