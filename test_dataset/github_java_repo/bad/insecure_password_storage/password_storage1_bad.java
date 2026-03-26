import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Insecure%20Password%20Storage.md

public class VulnerablePasswordStorage {

    public static void main(String[] args) {
        String username = "user123";
        String plainPassword = "insecurePassword";

        // Vulnerable: Storing plain text password in the database
        storePasswordInsecurely(username, plainPassword);
    }

    public static void storePasswordInsecurely(
        String username,
        String password
    ) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                "username",
                "password"
            );
            String query =
                "INSERT INTO users (username, password) VALUES (?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            pstmt.setString(2, password); // Vulnerable: Storing plain text password

            pstmt.executeUpdate();
            pstmt.close();
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
