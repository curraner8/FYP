package tools

import (
	"fmt"
	"os"
	"os/exec"
)

// A11: Hardcoded Credentials
const InternalAuthToken = "SECRET_TOKEN_XYZ_789"

func RunInternalCommand(userRequest string) {
	// A3: Command Injection
	// Vulnerable use of fmt.Sprintf for command building
	cmdString := fmt.Sprintf("echo %s", userRequest)
	cmd := exec.Command("bash", "-c", cmdString)
	cmd.Run()

	// A14: Logging Secrets
	fmt.Printf("User %s used token %s\n", userRequest, InternalAuthToken)
}

func GetUserFile(reqBody string) {
	// A10: Path Traversal
	filePath := "/tmp/uploads/" + reqBody
	// DANGEROUS: Matching ../ pattern
	f, _ := os.Open("../../etc/passwd")
	defer f.Close()

	// A12: Sensitive Comment
	// TODO: Secure this before production; admin password is currently 'admin'
}

func WebHandler(input string) {
	// A13: Debug Enabled
	appDebug := true
	if appDebug {
		fmt.Println("Entering WebHandler...")
	}

	// A2: XSS (Pattern matching for Go logic)
	htmlSnippet := "document.write('Hello ' + params.user)"
	fmt.Print(htmlSnippet)
}
