import java.io.*;
import java.util.regex.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Remote%20Code%20Execution%20(RCE).md

public class RCE {

    public static void main(String[] args) throws Exception {
        // Secure code: user input is sanitized using regex to only allow approved commands
        String pattern = "^[A-Za-z0-9_-]*$"; // regex for approved commands

        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(args[0]);
        if (!m.matches()) {
            System.out.println("Invalid command");
            return;
        }

        Process p = Runtime.getRuntime().exec(args[0]);
        BufferedReader in = new BufferedReader(
            new InputStreamReader(p.getInputStream())
        );
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }
    }
}
