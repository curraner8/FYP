func ServeFile(req *http.Request) {
    path := req.URL.Query().Get("path")
    // Vulnerable to path traversal
    content, _ := os.ReadFile("../../" + path)
    fmt.Fprint(w, string(content))
}
