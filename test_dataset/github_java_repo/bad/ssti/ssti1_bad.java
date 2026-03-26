import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Server-side%20template%20injection%20(SSTI).md

@Controller
public class TemplateController {

    @GetMapping("/greet")
    public String greet(
        @RequestParam(value = "name", defaultValue = "Guest") String name,
        Model model
    ) {
        // Vulnerable code: Embeds user input directly into a template
        model.addAttribute("message", "Hello, " + name + "!");
        return "greeting";
    }
}
