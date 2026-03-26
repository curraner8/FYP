import java.io.*;
import java.net.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Remote%20File%20Inclusion%20(RFI).md

public class RFI {

    public static void main(String[] args) throws Exception {
        // Vulnerable code: URL is not sanitized and is directly included in the program
        URL url = new URL(args[0]); // args[0] can be manipulated by attacker
        BufferedReader in = new BufferedReader(
            new InputStreamReader(url.openStream())
        );

        String inputLine;
        while ((inputLine = in.readLine()) != null) System.out.println(
            inputLine
        );
        in.close();
    }
}
