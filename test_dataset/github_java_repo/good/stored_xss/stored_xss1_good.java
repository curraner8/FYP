// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Stored%20Cross-Site-Scripting%20(XSS).md

public class ProfileServlet extends HttpServlet {

    protected void doPost(
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        String name = request.getParameter("name");
        String bio = request.getParameter("bio");
        String website = request.getParameter("website");

        // Sanitize user input
        name = sanitizeInput(name);
        bio = sanitizeInput(bio);
        website = sanitizeInput(website);

        User user = new User();
        user.setName(name);
        user.setBio(bio);
        user.setWebsite(website);

        // Save the user profile
        saveUserProfile(user);

        // Redirect to the profile page
        response.sendRedirect("/profile");
    }

    private String sanitizeInput(String input) {
        return input.replaceAll("<", "<").replaceAll(">", ">");
    }
}
