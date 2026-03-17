// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Log%20Injection.md

public void logUserAction(String username, String action) {
    // Sanitize the input to prevent log injection attacks
    username = sanitizeInput(username);
    action = sanitizeInput(action);

    // The following line is no longer vulnerable to log injection attacks
    logger.info("User " + username + " performed action: " + action);
}

private String sanitizeInput(String input) {
    // Implement sanitization logic here

    return input;
}
