import java.io.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Java%20Deserialization.md

public class VulnerableDeserialization {

    public static void main(String[] args) {
        try {
            // Deserialize data from a file
            FileInputStream fileIn = new FileInputStream("data.ser");
            ObjectInputStream in = new ObjectInputStream(fileIn);

            // Deserialize the object and cast it
            Object obj = in.readObject(); // Vulnerable point

            // Do something with the deserialized object
            // For a real attack, an attacker could place malicious code here.
            System.out.println("Deserialized object: " + obj.toString());

            in.close();
            fileIn.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
