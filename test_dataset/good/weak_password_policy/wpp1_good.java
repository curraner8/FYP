import java.util.regex.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Weak%20Password%20Policy.md

public class StrongPasswordPolicy {

    public static boolean isValidPassword(String password) {
        // Strong password policy: At least 8 characters, at least 1 special character, at least 1 number
        String regex = "^(?=.*[0-9])(?=.*[!@#$%^&*])(?=\\S+$).{8,}$";
        return Pattern.matches(regex, password);
    }
}
