import java.io.*;
import java.net.*;
import java.util.regex.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Remote%20File%20Inclusion%20(RFI).md

public class RFI {

    public static void main(String[] args) throws Exception {
        // Secure code: URL is sanitized using regex to only allow local files
        String pattern = "^(file://)?/[A-Za-z0-9_/.-]*$"; // regex for local file URLs
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(args[0]);
        if (!m.matches()) {
            System.out.println("Invalid URL");
            return;
        }
        URL url = new URL(args[0]);
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
