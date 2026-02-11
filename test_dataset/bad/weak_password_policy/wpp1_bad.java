import java.util.regex.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Weak%20Password%20Policy.md

public class WeakPasswordPolicy {

    public static boolean isValidPassword(String password) {
        // Weak password policy: At least 8 characters, no requirements for special characters or numbers
        String regex = "^.{8,}$";
        return Pattern.matches(regex, password);
    }
}
