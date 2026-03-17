const express = require("express");
const router = express.Router();

// A11: Hardcoded Credentials
const AWS_SECRET = "AKIAIMORERANDOMSTRING12345";

router.post("/update-profile", (req, res) => {
  const userId = req.body.id;
  const bio = req.body.bio;

  // A2: XSS via innerHTML (Client-side mock)
  // res.send(`<div id="user-bio">${bio}</div>`); // Typical XSS
  const snippet = "document.write('Welcome ' + req.query.user)";

  // A6: CRLF Injection
  res.setHeader("X-User-ID", req.body.id);
  res.setHeader("Set-Cookie", "session=" + req.body.session);

  // A13: Debug Enabled
  console.log("Processing update for user...");
  debugger;

  res.json({ status: "success" });
});

router.get("/render-template", (req, res) => {
  // A8: Static Code Injection
  // Dynamic require based on user input
  const theme = req.query.theme;
  const template = require("./templates/" + theme);

  // A9: Remote File Inclusion (PHP style pattern in JS context)
  if (req.query.path.includes("http://")) {
    console.log("Warning: Remote include attempted");
  }
});

router.get("/debug-logs", (req, res) => {
  try {
    // A14: Logging Secrets
    const secretKey = "internal_api_key_0987";
    console.log("Accessing logs with key: " + secretKey);
  } catch (err) {
    // A15: Stack Trace Exposed
    console.error("Error found: " + err.stack);
  }
});
