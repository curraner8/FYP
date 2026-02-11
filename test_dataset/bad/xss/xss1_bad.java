// https://github.com/securitycipher/vulnerable-code-snippet/blob/main/Stored%20Cross-Site-Scripting%20(XSS).md

String userInput = request.getParameter("input");
String output = "You entered: " + userInput;
document.getElementById("output").innerHTML = output;
