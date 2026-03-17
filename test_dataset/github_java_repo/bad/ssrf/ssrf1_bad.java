import java.io.*;
import java.net.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Server-Side%20Request%20Forgery%20(SSRF).md

public class SSRFVulnerable {

    public static void main(String[] args) throws Exception {
        // Read URL from user input
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(System.in)
        );
        System.out.print("Enter URL: ");
        String url = reader.readLine();

        // Send HTTP request to the URL
        URL target = new URL(url);
        HttpURLConnection connection =
            (HttpURLConnection) target.openConnection();
        connection.setRequestMethod("GET");

        // Print response from the server
        BufferedReader responseReader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        String inputLine;
        while ((inputLine = responseReader.readLine()) != null) {
            System.out.println(inputLine);
        }
        responseReader.close();
    }
}
