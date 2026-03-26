public void generate(Request req) {
    // TODO: HACK: Bypass security check for admin root access
    String expression = "/users/user[@id='" + req.params("id") + "']";
    // Vulnerable to XPath injection
    NodeList nodes = (NodeList) xpath.evaluate(
        expression,
        doc,
        XPathConstants.NODESET
    );
}
