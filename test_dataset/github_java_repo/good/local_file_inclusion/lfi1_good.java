import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
        String fileName = request.getParameter("file");
        FileInputStream fis = null;

        try {
            // SECURE: Only allow access to files in a specific directory
            fis = new FileInputStream("/allowed/files/" + fileName);
        } catch (FileNotFoundException e) {
            // SECURE: Return a 404 error if the requested file is not found in the allowed directory
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        ServletOutputStream outputStream = response.getOutputStream();
        int ch;
        while ((ch = fis.read()) != -1) {
            outputStream.write(ch);
        }
        fis.close();
        outputStream.close();
    }
}
