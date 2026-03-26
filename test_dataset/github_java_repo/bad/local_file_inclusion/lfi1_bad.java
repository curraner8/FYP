import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Local%20File%20Inclusion(LFI).md

public class FileInclusionServlet extends HttpServlet {

    protected void doGet(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        // VULNERABLE: The value of the "file" parameter is used to construct the path to a file on the server
        String fileName = request.getParameter("file");
        FileInputStream fis = new FileInputStream(fileName);
        ServletOutputStream outputStream = response.getOutputStream();

        int ch;
        while ((ch = fis.read()) != -1) {
            outputStream.write(ch);
        }
        fis.close();
        outputStream.close();
    }
}
