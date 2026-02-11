import java.io.StringReader;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/XXE%20%20injection.md

public class SecureXXE {

    public static void main(String[] args) throws Exception {
        String xmlData =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<user><name>John</name></user>";

        // Secure code: Disable external entity processing
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Document document = factory
            .newDocumentBuilder()
            .parse(new InputSource(new StringReader(xmlData)));

        // Processing the document
        String name = document
            .getElementsByTagName("name")
            .item(0)
            .getTextContent();
        System.out.println("Name: " + name);
    }
}
