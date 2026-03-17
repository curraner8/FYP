import java.io.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Remote%20Code%20Execution%20(RCE).md

public class RCE {

    public static void main(String[] args) throws Exception {
        // Vulnerable code: user input is directly passed to the system command
        Process p = Runtime.getRuntime().exec(args[0]); // args[0] can be manipulated by attacker
        BufferedReader in = new BufferedReader(
            new InputStreamReader(p.getInputStream())
        );
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }
    }
}
