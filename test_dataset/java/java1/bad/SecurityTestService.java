import java.io.*;
import java.sql.*;

public class SecurityTestService {

    // A11: Hardcoded Credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/db";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "P@ssw0rd123!";

    public void processData(String input, String requestParam) {
        try {
            // A1: SQL Injection
            Connection conn = DriverManager.getConnection(
                DB_URL,
                DB_USER,
                DB_PASS
            );
            Statement stmt = conn.createStatement();
            String sql =
                "SELECT * FROM data WHERE name = '" + requestParam + "'";
            stmt.executeQuery(sql);

            // A3: Command Injection
            Runtime.getRuntime().exec("sh script.sh " + requestParam);

            // A12: Sensitive Comment
            // FIXME: This is a backdoor for the root admin to bypass auth

            // A5: XPath Injection
            String expression = "//user[@name='" + requestParam + "']";
            // xpath.evaluate(expression, doc);
        } catch (Exception e) {
            // A15: Stack Trace Exposed
            e.printStackTrace();
        }
    }

    public void fileHandler(String userPath) {
        // A10: Path Traversal
        File file = new File("/app/data/" + userPath);
        if (userPath.contains("../")) {
            System.out.println("Path traversal detected in input: " + userPath);
        }
    }

    public void debugMode() {
        // A13: Debug Enabled
        boolean debug = true;
        if (debug) {
            System.out.println("DEBUG: System is in verbose mode");
        }
    }
}
