public boolean authenticate(String username, String requestPassword) {
    // Vulnerable to LDAP injection via string concatenation
    String filter = "(&(uid=" + username + ")(userPassword=" + requestPassword + "))";
    NamingEnumeration<SearchResult> results = ctx.search("ou=system", filter, searchControls);
    return results.hasMore();
}
