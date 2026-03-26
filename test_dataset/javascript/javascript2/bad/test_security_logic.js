function ProcessData(input) {
  // B1: Using eval to parse logic is a massive hole
  const result = eval("7 + " + input);

  // B8: Math.random is PRNG and not cryptographically secure
  const sessionID = Math.random().toString(36).substring(2);

  console.log("Result:", result, "Session:", sessionID);
}
