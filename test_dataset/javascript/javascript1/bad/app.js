app.get("/process", (req, res) => {
  const userInput = req.query.data;

  // 1. Eval Injection
  const result = eval("ops." + userInput);

  // 2. CRLF Injection
  res.setHeader("X-Process-ID", req.query.id);

  // 3. XSS (Reflected)
  document.write("Result: " + userInput);
});
