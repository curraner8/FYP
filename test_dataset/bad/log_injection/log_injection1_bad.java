// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Log%20Injection.md

public void logUserAction(String username, String action) {
    // The following line is vulnerable to log injection attacks
    logger.info("User " + username + " performed action: " + action);
}
