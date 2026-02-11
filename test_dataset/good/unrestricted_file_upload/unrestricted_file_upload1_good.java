import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Unrestricted%20File%20Upload.md

@WebServlet("/upload")
@MultipartConfig
public class SecureFileUploadServlet extends HttpServlet {

    private static final String UPLOAD_DIRECTORY = "/uploads/";
    private static final int MAX_FILE_SIZE = 1024 * 1024; // 1 MB

    protected void doPost(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws ServletException, IOException {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();

        // Check file type (allow only image files)
        if (
            fileName.endsWith(".jpg") ||
            fileName.endsWith(".png") ||
            fileName.endsWith(".gif")
        ) {
            InputStream fileContent = filePart.getInputStream();
            File uploadedFile = new File(
                getServletContext().getRealPath("") +
                    UPLOAD_DIRECTORY +
                    fileName
            );

            if (filePart.getSize() <= MAX_FILE_SIZE) {
                try (
                    OutputStream outputStream = new FileOutputStream(
                        uploadedFile
                    )
                ) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fileContent.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
                response.getWriter().println("File uploaded successfully.");
            } else {
                response.getWriter().println("File size exceeds the limit.");
            }
        } else {
            response.getWriter().println("Invalid file type.");
        }
    }
}
