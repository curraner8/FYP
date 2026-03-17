import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Stored%20Cross-Site-Scripting%20(XSS).md

PolicyFactory policy = new HtmlPolicyBuilder()

.allowElements("a")
.allowUrlProtocols("https")
.allowAttributes("href").onElements("a")
.toFactory();

String userInput = request.getParameter("input");
String output = policy.sanitize(userInput);
document.getElementById("output").innerHTML = "You entered: " + output;
