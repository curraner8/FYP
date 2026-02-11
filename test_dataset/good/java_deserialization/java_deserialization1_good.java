import java.io.*;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Java%20Deserialization.md

public class SecureDeserialization {

    public static void main(String[] args) {
        try {
            // Deserialize data from a file
            FileInputStream fileIn = new FileInputStream("data.ser");
            ObjectInputStream in = new ObjectInputStream(fileIn);

            // Deserialize the object and cast it safely
            Object obj = in.readObject();

            // Perform type checking to ensure the deserialized object is of the expected type
            if (obj instanceof SomeClass) {
                SomeClass secureObject = (SomeClass) obj;
                // Use the deserialized object safely
                System.out.println(
                    "Deserialized object: " + secureObject.toString()
                );
            } else {
                System.out.println(
                    "Invalid object type. Aborting deserialization."
                );
            }

            in.close();
            fileIn.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
