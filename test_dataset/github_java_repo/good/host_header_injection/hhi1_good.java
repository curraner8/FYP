import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Host%20Header%20Injection.md

public class PasswordResetServlet {

    private static final String APP_DOMAIN = "example.com";

    public void resetPassword(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws IOException {
        String email = request.getParameter("email");
        String resetLink =
            "https://" + APP_DOMAIN + "/reset-password?email=" + email;

        // Send password reset link to the user's email
        // ...

        response.sendRedirect(resetLink);
    }
}
