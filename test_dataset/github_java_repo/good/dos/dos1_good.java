import java.io.*;
import java.net.*;
import java.util.concurrent.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Application-level%20Denial%20of%20Service%20(DoS).md

public class SecureDoSApp {

    private static final int MAX_THREADS = 10;
    private static final ExecutorService executor =
        Executors.newFixedThreadPool(MAX_THREADS);

    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            while (true) {
                Socket socket = serverSocket.accept();
                executor.execute(new RequestHandler(socket));
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
            // Simulate some processing
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
