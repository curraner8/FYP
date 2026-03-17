import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Insecure%20Password%20Reset%20%E2%80%93%20Token%20Exposed%20in%20Response.md

public class InsecurePasswordReset {

    // Vulnerable method for sending reset token in the response
    public Map<String, String> requestPasswordReset(String email) {
        // Check if the email exists in the system (simplified for illustration)
        if (userExists(email)) {
            // Generate a reset token (UUID for simplicity)
            String resetToken = UUID.randomUUID().toString();

            // Send the reset token in the response
            Map<String, String> response = new HashMap<>();
            response.put("message", "Reset token sent to your email.");
            response.put("resetToken", resetToken);
            return response;
        } else {
            // User does not exist
            Map<String, String> response = new HashMap<>();
            response.put("message", "Email not found in our system.");
            return response;
        }
    }

    // Check if the user exists (simplified for illustration)
    private boolean userExists(String email) {
        // Simulated database lookup
        return true; // Assume user exists for this example
    }

    public static void main(String[] args) {
        InsecurePasswordReset resetService = new InsecurePasswordReset();
        Map<String, String> response = resetService.requestPasswordReset(
            "user@example.com"
        );
        System.out.println(response);
    }
}
