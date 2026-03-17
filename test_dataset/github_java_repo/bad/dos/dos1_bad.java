import java.io.*;
import java.net.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Application-level%20Denial%20of%20Service%20(DoS).md

public class VulnerableDoSApp {

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            while (true) {
                Socket socket = serverSocket.accept();
                Thread thread = new Thread(new RequestHandler(socket));
                thread.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class RequestHandler implements Runnable {

    private final Socket socket;

    public RequestHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            // Simulate some heavy processing
            Thread.sleep(1000);

            // Read the request and send a response
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream())
            );
            PrintWriter writer = new PrintWriter(
                socket.getOutputStream(),
                true
            );
            String request = reader.readLine();
            writer.println("Response to: " + request);

            // Close the socket
            socket.close();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
