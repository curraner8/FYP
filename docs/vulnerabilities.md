
##### **OWASP Top 10 2025:**
https://owasp.org/Top10/2025/0x00_2025-Introduction/

1. ==**Broken Access Control:**==
   The most serious application security risk according to OWASP Top 10 2025. The contributed data indicates that on average, 3.73% of applications tested had one or more of the 40 *Common Weakness Enumerations (CWEs)* in this category. **Server-Side Request Forgery (SSRF)** has been rolled into this category.

2. ==**Security Misconfiguration:**==
   Misconfigurations are more prevalent in the data for this cycle, with 3.00% of the applications tested having one or more of the *16 CWEs* in this category. Not surprising, as software engineering is continuing to increase the amount of an application's behaviour that is based on configurations.

3. ==**Software Supply Chain Failures:**==
   An expansion of **Vulnerable and Outdated Components** to include a broader scope of compromises occurring within or across the entire ecosystem of software dependencies, build systems, and distribution infrastructure. This category was overwhelmingly voted a top concern in the community survey. This category has *5 CWEs* and a limited presence in the collected data, but OWASP believe this is due to challenges in testing and hopes that testing catches up in this area. This category has the fewest occurrences in the data, but also the highest average exploit and impact scores from CVEs.

4. ==**Cryptographic Failures:**==
   The contributed data indicates that, on average, 3.80% of applications have one or more of the *32 CWEs* in this category. This category often leads to sensitive data exposure or system compromise.

5. ==**Injection:**==
   Injection is one of the most tested categories, with the greatest number of CVEs associated with the *38 CWEs* in this category. Injection includes a range of issues from **Cross-Site Scripting** (high frequency/low impact) to **SQL Injection** (low frequency/high impact) vulnerabilities.

6. ==**Insecure Design:**==
   This category was introduced in 2021, and noticeable improvements have been seen in the industry related to threat modeling and a greater emphasis on secure design.

7. ==**Authentication Failures:**==
   With a slight name change from **Identification and Authentication Failures** to more accurately reflect the *36 CWEs* in this category. This category remains important, but the increased use of standardized frameworks for authentication appears to be having beneficial effects on the occurrences of authentication failures.

8. ==**Software or Data Integrity Failures:**==
   This category is focused on the failure to maintain trust boundaries and verify the integrity of software code, and data artifacts at a lower level than Software Supply Chain Failures.

9. ==**Security Loggings and Alerting Failures:**==
   Great logging with no alerting is of minimal value in identifying security incidents. This category will always be underrepresented in the data, and was again voted into a position in the list from the community survey participants.

10. ==**Mishandling of Exceptional Conditions:**==
    This category contains *24 CWEs* focusing on improper error handling, logical errors, failing open, and other related scenarios stemming from abnormal conditions that systems may encounter.

##### **Weaknesses in the 2025 CWE Top 25 Most Dangerous Software Weaknesses**
https://cwe.mitre.org/data/definitions/1435.html

- ==**Improper Neutralization of Input During Web Page Generation**== ('Cross-site Scripting') 

- ==**Improper Neutralization of Special Elements used in an SQL Command**== ('SQL Injection) 

- ==**Out of bounds Write:**== The product writes data past the end, or before the beginning, of the intended buffer. 

- ==**Cross-Site Request Forgery:**== The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor. 

- ==**Missing Authorization**== 

- ==**Improper Limitation of a Pathname to a Restricted Directory**== ('Path Traversal'): The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside the restricted directory. 

- ==**Use After Free:**== The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because the memory "belongs" to the code that operates on the new pointer.

- ==**Out-of-bounds Read:**== The product reads data past the end, or before the beginning, of the intended buffer.

- ==**Improper Control of Generation of Code:**== ('Code Injection'): The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behaviour of the intended code segment. 

- ==**Unrestricted Upload of File with Dangerous Type:**== The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.

- ==**NULL Pointer Dereference:**== The product dereferences a pointer that it expects to be valid but is NULL.

- ==**Exposure of Sensitive Information to an Unauthorized Actor**==

- ==**Improper Authentication:**== When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

- ==**Improper Privilege Management:**== The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

- ==**Deserialization of Untrusted Data:**== The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.

- ==**Improper Input Validation:**== The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

- ==**Incorrect Authorization:**== The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.

- ==**Missing Authentication for Critical Function:**== The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

### **CWE Category: OWASP Top 10 02: Security Misconfiguration
https://cwe.mitre.org/data/definitions/1437.html

- ==**J2EE Misconfiguration: Data Transmission Without Encryption:**== Information sent over a network can be compromised while in transit. An attacker may be able to read or modify the contents if the data are sent in plaintext or are weakly encrypted.

- ==**ASP.NET Misconfiguration: Creating Debug Library:**== Debugging messages help attackers learn about the system and plan a form of attack.

- ==**ASP.NET Misconfiguration: Password in Configuration File:**== Storing a plaintext password in a configuration file allows anyone who can read the file access to the password-protected resource making them an easy target for attackers.

- ==**CWE-15: External Control of System or Configuration Setting:**== One or more system settings or configuration elements can be externally controlled by a user.

###### **Configuration**
- ==**Generation of Error Message Containing Sensitive Information**==
- ==**Insertion of Sensitive Information Into Debugging Code**==
- ==**Exposure of Information Through Directory Listing**==

- ==**Cleartext Storage of Sensitive Information in a Cookie:**== The product stores sensitive information in cleartext in a cookie.

- ==**Active Debug Code:**== The product is released with debugging code still enabled or active.

- ==**Cleartext Storage of Sensitive Information in an Environment Variable:**== The product uses an environment variable to store unencrypted sensitive information.

- ==**Use of Hard-coded, Security-relevant Constants:**== The product uses hard-coded constants instead of symbolic names for security-critical values, which increases the likelihood of mistakes during code maintenance or security policy change.

- ==**Improper Restriction of XML External Entity References:**== The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its outputs.

- ==**Sensitive Cookie in HTTPS Session Without 'Secure' Attribute:**== The Secure attribute for sensitive cookies in HTTPS sessions is not set.

- ==**Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion'):**== The product uses XML documents and allows their structure to be defined with a Document Type Definition (DTD), but it does not properly control the number of recursive definitions of entities.

- ==**Permissive Cross-domain Security Policy with Untrusted Domains:**== The product uses a web-client protection mechanism such as a Content Security Policy (CSP) or cross-domain policy file, but the policy includes untrusted domains with which the web client is allowed to communicate.

- ==**Sensitive Cookie Without 'HttpOnly' Flag:**== The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.

- ==**ASP.NET Misconfiguration: Improper Model Validation:**== The ASP.NET application does not use, or incorrectly uses, the model validation framework.
### **CWE Category: OWASP Top 10 01: Broken Access Control**
https://cwe.mitre.org/data/definitions/1436.html

- ==**Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'):**== The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.

- ==**Relative Path Traversal:**== The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory.

- ==**Absolute Path Traversal:**== The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as "/abs/path" that can resolve to a location that is outside of that directory.

- ==**Improper Link Resolution Before File Access ('Link Following'):**== The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

- ==**UNIX Symbolic Link (Symlink) Following:**== The product, when opening a file or directory, does not sufficiently account for when a file is a symbolic link that resolves to a target outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

- ==**Windows Hard Link:**== The product, when opening a file or directory, does not sufficiently handle when the name is associated with a hard link to a target that is outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

- ==**Exposure of Sensitive Information to an Unauthorized Actor:**== The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

- ==**Insertion of Sensitive Information Into Sent Data:**== The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

- ==**Storage of File with Sensitive Data Under Web Root:**== The product stores sensitive data under the web document root with insufficient access control, which might make it accessible to untrusted parties.

- ==**Incorrect Default Permissions:**== During installation, installed file permissions are set to allow anyone to modify those files.

- ==**Improper Preservation of Permissions:**== The product does not preserve permissions or incorrectly preserves permissions when copying, restoring, or sharing objects, which can cause them to have less restrictive permissions than intended.

- ==**Improper Ownership Management:**== The product assigns the wrong ownership, or does not properly verify the ownership, of an object or resource.

- ==**Unverified Ownership:**== The product does not properly verify that a critical resource is owned by the property entity.

- ==**Improper Access Control:**== The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

- ==**Improper Authorization:**== The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

- ==**Cross-Site Request Forgery (CSRF):**== The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.

- ==**Exposure of Private Personal Information to an Unauthorized Actor:**== The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent of the person whom the information is collected.

- ==**Insecure Temporary File:**== Creating and using insecure temporary files can leave application and system data vulnerable to attack.

- ==**Creation of Temporary File in Directory with Insecure Permissions:**== The product creates a temporary file in a directory whose permissions allow unintended actors to determine the file's existence or otherwise access that file.

- ==**Transmission of Private Resources into a New Sphere ('Resource Leak'):**== The product makes resources available to untrusted parties when those resources are only intended to be accessed by the product.

- ==**Improper Protection of Alternate Path:**== The product does not sufficiently protect all possible paths that a user can take to access restricted functionality or resources.

- ==**Direct Request ('Forced Browsing'):**== The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.

- ==**Unintended Proxy or Intermediary ('Confused Deputy'):**== The product receives a request, message, or directive from an upstream component, but the product does not sufficiently preserve the original source of the request before forwarding the request to an external actor that is outside of the product's control sphere. This causes the product to appear to be the source of the request, leading it to act as a proxy or other intermediary between the upstream component and the external actor.

- ==**Exposure of Sensitive System Information to an Unauthorized Control Sphere:**== The product does not properly prevent sensitive system-level information from being accessed by unauthorized actors who do not have the same level of access to the underlying system as the product does.

- ==**Insertion of Sensitive Information to Externally-Accessible File or Directory:**== The product places sensitive information into files or directories that are accessible to actors who are allowed to have access to the files, but not to the sensitive information.

- ==**Inclusion of Sensitive Information in Source Code:**== Source code on a web server or repository often contains sensitive information and should generally not be accessible to users.

- ==**Exposure of Information Through Directory Listing:**== The product inappropriately exposes a directory listing with an index of all the resources located inside of the directory.

- ==**Files of Directories Accessible to External Parties:**== The product makes files or directories accessible to unauthorized actors, even though they should not be.

- ==**Authorization Bypass Through User-Controlled SQL Primary Key:**== The product uses a database table that includes records that should not be accessible to an actor, but it executes a SQL statement with a primary key that can be controlled by that actor.

- ==**URL Redirection to Untrusted Site ('Open Redirect'):**== The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.

- ==**Inclusion of Sensitive Information in Source Code Comments**==

- ==**Authorization Bypass Through User-Controlled Key:**== The system/s authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.

- ==**Exposure of Resource to Wrong Sphere:**== The product exposes a resource to the wrong control sphere, providing unintended actors with inappropriate access to the resource.

- ==**Incorrect Permission Assignment for Critical Resource:**== The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.

- ==**Exposed Dangerous Method or Function:**== The product provides an Applications Programming Interface (API) or similar interface for interaction with external actors, but the interface includes a dangerous method or function that is not properly restricted.

- ==**Missing Authorization**==

- ==**Incorrect Authorization**==

- ==**Server-Side Request Forgery (SSRF):**== The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.

- ==**Insecure Storage of Sensitive Information:**== The product stores sensitive information without properly limiting read or write access by unauthorized actors.

- ==**Sensitive Cookie with Improper SameSite Attribute:**== The SameSite attribute for sensitive cookies is not set, or an insecure value is used.

### **CWE Category: OWASP Top 10 03: Software Supply Chain Failures**
https://cwe.mitre.org/data/definitions/1438.html

- ==**Unimplemented or Unsupported Feature in UI:**== A UI function for a security feature appears to be supported and gives feedback to the user that suggests that it is supported, but the underlying functionality is not implemented.

- ==**Use of Obsolete Function:**== The code uses deprecated or obsolete functions, which suggests that the code has not been actively reviewed or maintained.

###### **Using Components with Known Vulnerabilities:**
Weaknesses in this category are related to the A9 category in the OWASP Top Ten 2017.

- ==**Use of Unmaintained Third Party Components:**== The product relies on third-party components that are not actively supported or maintained by the original developer or a trusted proxy for the original developer.

- ==**Reliance on Component That is Not Updateable:**== The product contains a component that cannot be updated or patched in order to remove vulnerabilities or significant bugs.

- ==**Dependency on Vulnerable Third-Party Component:**== The product has a dependency on a third-party component that contains one or more known vulnerabilities.

### **CWE Category: OWASP Top 10 04: Cryptographic Failures**
https://cwe.mitre.org/data/definitions/1439.html

- ==**Weak Encoding for Password:**== Obscuring a password with trivial encoding does not protect the password.

- ==**Improper Following of a Certificate's Chain of Trust:**== The product does not follow, or incorrectly follows, the chain of trust for a certificate back to a trusted root certificate, resulting in incorrect trust of any resource that is associated with that certificate.

- ==**Cleartext Transmission of Sensitive Information:**== The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.

###### **Key Management Errors**
- ==**Key Exchange without Entity Authentication**==
- ==**Reusing a Nonce, Key Pair in Encryption**==
- ==**Use of a Key Past its Expiration Date**==
- ==**Use of Hard-coded Credentials**==

- ==**Missing Cryptographic Step:**== The product does not implement a required step in a cryptographic algorithm, resulting in weaker encryption than advertised by the algorithm.

- ==**Inadequate Encryption Strength:**== The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.

- ==**Use of a Broken or Risky Cryptographic Algorithm:**== The product uses a broken or risky cryptographic algorithm or protocol.

- ==**Use of Weak Hash:**== The product uses an algorithm that produces a digest (output value) that does not meet security expectations for a hash function that allows an adversary to reasonably determine the original input (preimage attack), find another input that can be produced for the same hash (2nd preimage attack), or find multiple inputs that evaluate to the same hash (birthday attack).

- ==**Generation of Predictable IV with CBC Mode:**== The product generates and uses a predictable Initialization Vector (IV) with Cipher Block Chaining (CBC) Mode, which causes algorithms to be susceptible to dictionary attacks when they are encrypted under the same key.

- ==**Use of Insufficiently Random Values:**== The product uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.

- ==**Insufficient Entropy:**== The product uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others.

- ==**Insufficient Entropy in PRNG:**== The lack of entropy available for, or used by, a Pseudo-Random Number Generator can be a stability and security threat.

- ==**Small Space of Random Values:**== The number of possible random values is smaller than needed by the product, making it more susceptible to brute force attacks.

- ==**Incorrect Usage of Seeds in PRNG:**== The product uses a PRNG but does not correctly manage seeds.

- ==**Same Seed in PRNG:**== A PRNG uses the same seed each time the product is initialized.

- ==**Predictable Seed in PRNG:**== A PRNG is initialized from a predictable seed, such as the process ID or system time.

- ==**Use of a Cryptographically Weak PRNG:**== The product uses a PRNG in a security context, but the PRNG's algorithm is not cryptographically strong.

- ==**Generation of Predictable Numbers or Identifiers:**== The product uses a scheme that generates numbers or identifiers that are more predictable than required.

- ==**Predictable Exact Values from Previous Values:**== An exact value or random number can be precisely predicted by observing previous values.

- ==**Improper Verification of Cryptographic Signature:**== The product does not verify, or incorrectly verifies, the cryptographic signature for data.

- ==**Unprotected Transport of Credentials:**== Login pages do not use adequate measures to protect the user name and password while they are in transit from the client to the server.

- ==**Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade'):**== A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it does not select the strongest algorithm that is available to both parties.

- ==**Use of a One-Way Hash without a Salt:**== The product uses a one-way cryptographic hash against an input that should not be reversible, such as a password, but the product does not also use a salt as part of the input.

- ==**Use of a One-Way Has with a Predictable Salt:**== The product uses a one-way cryptographic hash against an input that should not be reversible, such as a password, but the product uses a predictable salt as part of the input.

- ==**Use of RSA Algorithm without OAEP:**== The product uses the RSA algorithm but does not incorporate Optimal Asymmetric Encryption Padding (OAEP), which might weaken the encryption.

- ==**Use of Password Hash With Insufficient Computational Effort:**== The product generates a hash for a password, but it uses a scheme that does not provide a sufficient level of computational effort that would make password cracking attacks infeasible or expensive.

- ==**Use of a Cryptographic Primitive with a Risky Implementation:**== To fulfill the need for a cryptographic primitive, the product implements a cryptographic algorithm using a non-standard, unproven, or disallowed/non-compliant cryptographic implementation.

- ==**Use of Predictable Algorithm in Random Number Generator:**== The device uses an algorithm that is predictable and generates a pseudo-random number.

### **CWE Category: OWASP Top 10 05: Injection**
https://cwe.mitre.org/data/definitions/1440.html

- ==**Improper Input Validation:**== The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to access the data safely and correctly.

- ==**Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection'):**== The product constructs all or part of a command, data structure, or record using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.

- ==**Improper Neutralization of Equivalent Special Elements:**== The product correctly neutralizes certain special elements, but it improperly neutralizes equivalent special elements.

- ==**Improper Neutralization of Special Elements used in a Command ('Command Injection'):**== The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.

- ==**Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'):**== The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

- ==**Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'):**== The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

- ==**Improper Neutralization of Script-Related HTML Tags in a Web Page ('Basic XSS'):**== The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as "<", ">", and "&" that could be interpreted as web-scripting elements when they are sent to a downstream component that processes web pages.

- ==**Improper Neutralization of Script in Attributes in a Web Page:**== The product does not neutralize or incorrectly neutralizes "`javascript:`" or other URIs from dangerous attributes within tags, such as `onmouseover`, `onload`, `onerror`, or `style`.

- ==**Improper Neutralization of Invalid Characters in Identifiers in Web Pages:**== The product does not neutralize or incorrectly neutralizes invalid characters or byte sequences in the middle of tag names, URI schemes, and other identifiers. Some web browsers may remove these sequences, resulting in output that may have unintended control implications. For example, the product may attempt to remove a "`javascript:`" URI scheme, but a "java%00script:" URI may bypass this check and still be rendered as active `javascript` by some browsers, allowing XSS or other attacks.

- ==**Improper Neutralization of Argument Delimiters in a Command ('Argument Injection'):**== The product constructs a string for a command to be executed by a separate component in another control sphere, but it does not properly delimit the intended arguments, options, or switches within that command string.

- ==**Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection'):**== The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.

- ==**Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'):**== The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

- ==**XML Injection (AKA Blind XPath Injection):**== The product does not properly neutralize special elements that are used in XML, allowing attackers to modify the syntax, content, or commands of the XML before it is processed by an end system.

- ==**Improper Neutralization of CRLF Sequences ('CRLF Injection'):**== The product uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.

- ==**Improper Control of Generation of Code ('Code Injection'):**== The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

- ==**Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection'):**== The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call (e.g. "eval").

- ==**Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection'):**== The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or template.

- ==**Improper Neutralization of Server-Side Includes (SSI) Within a Web Page:**== The product generates a web page, but does not neutralize or incorrectly neutralizes user-controllable input that could be interpreted as a server-side include (SSI) directive.

- ==**Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion'):**== The PHP application receives input from an upstream component, but it does not restrict or incorrectly restricts the input before its usage in "require," "include," or similar functions.

- ==**Improper Control of Resource Identifiers ('Resource Injection'):**== The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.

- ==**Struts: Incomplete `validate()` Method Definition:**== The product has a validator form that either does not define a `validate()` method, or defines a `validate()` method but does not call `super.validate()`.

- ==**Struts: Form Bean Does Not Extend Validation Class:**== If a form bean does not extend an `ActionForm` subclass of the Validator framework, it can expose the application to other weaknesses related to insufficient input validation.

- ==**Missing XML Validation:**== The product accepts XML from an untrusted source but does not validate the XML against the proper schema.

- ==**Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting'):**== The product receives data from an HTTP agent/component (e.g., web server, proxy, browser, etc.), but it does not neutralize or incorrectly neutralizes CR and LF characters before the data is included in outgoing HTTP headers.

- ==**Process Control:**== Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker.

- ==**Misinterpretation of Input:**== The product misinterprets an input, whether from an attacker or another product, in a security-relevant fashion.

- ==**Improper Encoding or Escaping of Output:**== The product prepares a structured message for communication with another component, but encoding or escaping of the data is either missing or done incorrectly. As a result, the intended structure of the message is not preserved.

- ==**Improper Validation of Array Index:**== The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position within the array.

- ==**Improper Handling of Invalid Use of Special Elements:**== The product does not properly filter, remove, quote, or otherwise manage the invalid use of special elements in user-controlled input, which could cause adverse effect on its behavior and integrity.

- ==**Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection'):**== The product uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.

- ==**Critical Public Variable Without Final Modifier:**== The product has a critical public variable that is not final, which allows the variable to be modified to contain unexpected values.

- ==**Public Static Field Not Marked Final:**== An object contains a public static field that is not marked final, which might allow it to be modified in unexpected ways.

- ==**SQL Injection: Hibernate:**== Using Hibernate to execute a dynamic SQL statement built with user-controlled input can allow an attacker to modify the statement's meaning or to execute arbitrary SQL commands.

- ==**Externally Controlled Reference to a Resource in Another Sphere:**== The product uses an externally controlled name or reference that resolves to a resource that is outside of the intended control sphere.

- ==**Improper Neutralization of Data within XPath Expressions ('XPath Injection'):**== The product uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input. This allows an attacker to control the structure of the query.

- ==**Improper Neutralization of HTTP Headers for Scripting Syntax:**== The product does not neutralize or incorrectly neutralizes web scripting syntax in HTTP headers that can be used by web browser components that can process raw headers, such as Flash.

- ==**Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection'):**== The product constructs all or part of an expression language (EL) statement in a framework such as a Java Server Page (JSP) using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended EL statement before it is executed.

### **CWE Category: OWASP Top 10 06: Insecure Design**
https://cwe.mitre.org/data/definitions/1441.html

- ==**External Control of File Name or Path:**== The product allows user input to control or influence paths or file names that are used in filesystem operations.

- ==**Permissive List of Allowed Inputs:**== The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are explicitly allowed by policy because the inputs are assumed to be safe, but the list is too permissive - that is, it allows an input that is unsafe, leading to resultant weaknesses.

- ==**Plaintext Storage of a Password:**== The product stores a password in plaintext within resources such as memory or files.

- ==**Incorrect Privilege Assignment:**== A product incorrectly assigns a privilege to a particular actor, creating an unintended sphere of control for that actor.

- ==**Improper Privilege Management:**== The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

- ==**Incorrect User Management:**== The product does not properly manage a user within its environment. Users can be assigned to the wrong group (class) of permissions resulting in unintended access rights to sensitive objects.

- ==**Missing Encryption of Sensitive Data:**== The product does not encrypt sensitive or critical information before storage or transmission.

- ==**Cleartext Storage of Sensitive Information:**== The product stores sensitive information in cleartext within a resource that might be accessible to another control sphere.

- ==**Cleartext Storage in a File or on Disk:**== The product stores sensitive information in cleartext in a file, or on disk. The sensitive information could be read by attackers with access to the file, or with physical or administrator access to the raw disk. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

- ==**Cleartext Storage of Sensitive Information in Memory:**== The product stores sensitive information in cleartext in memory. The sensitive memory might be saved to disk, stored in a core dump, or remain uncleared if the product crashes, or if the programmer does not properly clear the memory before freeing it. It could be argued that such problems are usually only exploitable by those with administrator privileges. However, swapping could cause the memory to be written to disk and leave it accessible to physical attack afterwards. Core dump files might have insecure permissions or be stored in archive files that are accessible to untrusted people. Or, uncleared sensitive memory might be inadvertently exposed to attackers due to another weakness.

- ==**Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'):**== The product contains a concurrent code sequence that requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence operating concurrently.

- ==**J2EE Bad Practices: Use of `System.exit()`:**== A J2EE application uses `System.exit()`, which also shuts down its container. It is never a good idea for a web application to attempt to shut down the application container. Access to a function that can shut down the application is an avenue for Denial of Service (DoS) attacks.

- ==**Unprotected Primary Channel:**== The product uses a primary channel for administration or restricted functionality, but it does not properly protect the channel.

- ==**Unrestricted Upload of File with Dangerous Type:**== The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.

- ==**Interpretation Conflict:**== Product A handles inputs or steps differently than Product B, which causes A to perform incorrect actions based on its perception of B's state.

- ==**Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling'):**== The product acts as an intermediary HTTP agent (such as a proxy or firewall) in the data flow between two entities such as a client and server, but it does not interpret malformed HTTP requests or responses in ways that are consistent with how the messages will be processed by those entities that are at the ultimate destination.

- ==**UI Misrepresentation of Critical Information:**== The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed. This is often a component in phishing attacks.

- ==**External Initialization of Trusted Variables or Data Stores:**== The product initializes critical internal variables or data stores using inputs that can be modified by untrusted actors.

- ==**External Control of Assumed-Immutable Web Parameter:**== The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.

- ==**Trust Boundary Violation:**== The product mixes trusted and untrusted data in the same data structure or structured message.

- ==**Insufficiently Protected Credentials:**== The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

- ==**Use of Web Browser Cache Containing Sensitive Information:**== The web application does not use an appropriate caching policy that specifies the extent to which each web page and associated form fields should be cached.

- ==**Use of Persistent Cookies Containing Sensitive Information:**== The web application uses persistent cookies, but the cookies contain sensitive information.

- ==**Use of GET Request Method With Sensitive Query Strings:**== The web application uses the HTTP GET method to process a request and includes sensitive information in the query string of that request.

- ==**Client-Side Enforcement of Server-Side Security:**== The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

- ==**Function Call with Incorrectly Specified Arguments:**== The product calls a function, procedure, or routine with arguments that are not correctly specified, leading to always-incorrect behavior and resultant weaknesses.

- ==**External Control of Critical State Data:**== The product stores security-critical state information about its users, or the product itself, in a location that is accessible to unauthorized actors.

- ==**Reliance of File Name or Extension of Externally-Supplied File:**== The product allows a file to be uploaded, but it relies on the file name or extension of the file to determine the appropriate behaviors. This could be used by attackers to cause the file to be misclassified and processed in a dangerous fashion.

- ==**Improper Isolation or Compartmentalization:**== The product does not properly compartmentalize or isolate functionality, processes, or resources that require different privilege levels, rights, or permissions.

- ==**Reliance on Security Through Obscurity:**== The product uses a protection mechanism whose strength depends heavily on its obscurity, such that knowledge of its algorithms or key data is sufficient to defeat the mechanism.

- ==**Violation of Secure Design Principles:**== The product violates well-established principles for secure design. This can introduce resultant weaknesses or make it easier for developers to introduce related weaknesses during implementation. Because code is centered around design, it can be resource-intensive to fix design problems.
	- ==**Improper Adherence to Coding Standards**==
	- ==**Execution with Unnecessary Privileges**==
	- ==**Not Failing Securely ('Failing Open')**==
	- ==**Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')**==
	- ==**Not Using Complete Mediation**==
	- ==**Improper Isolation or Compartmentalization**==
	- ==**Reliance on a Single Factor in a Security Decision**==
	- ==**Insufficient Psychological Acceptability**==
	- ==**Reliance on Security Through Obscurity**==
	- ==**Lack of Administrator Control over Security**==
	- ==**Improper Identifier for IP Block used in System-On-Chip (SOC)**==
	- ==**Dependency on Vulnerable Third-Party Component**==

- ==**Use of Potentially Dangerous Function:**== The product invokes a potentially dangerous function that could introduce a vulnerability if it is used incorrectly, but the function can also be used safely.

- ==**Protection Mechanism Failure:**== The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

- ==**Improper Control of Interaction Frequency:**== The product does not properly limit the number or frequency of interactions that it has with an actor, such as the number of incoming requests.

- ==**Reliance on Untrusted Inputs in a Security Decision:**== The product uses a protection mechanism that relies on the existence or values of an input, but the input can be modified by an untrusted actor in a way that bypasses the protection mechanism.

- ==**Improper Enforcement of Behavioral Workflow:**== The product supports a session in which more than one behavior must be performed by an actor, but it does not properly ensure that the actor performs the behaviors in the required sequence.

- ==**Improper Restriction of Rendered UI Layers or Frames:**== The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain, which can lead to user confusion about which interface the user is interacting with.

- ==**Use of Web Link to Untrusted Target with `window.opener` Access:**== The web application produces links to untrusted external sites outside of its sphere of control, but it does not properly prevent the external site from modifying security-critical properties of the `window.opener` object, such as the location property.

- ==**Excessive Attack Surface:**== The product has an attack surface whose quantitative measurement exceeds a desirable maximum. Originating from software security, an "attack surface" measure typically reflects the number of input points and output points that can be utilized by an untrusted party, i.e. a potential attacker. A larger attack surface provides more places to attack, and more opportunities for developers to introduce weaknesses. In some cases, this measure may reflect other aspects of quality besides security; e.g., a product with many inputs and outputs may require a large number of tests in order to improve code coverage.

### **CWE Category: OWASP Top 10 07: Authentication Failures**
https://cwe.mitre.org/data/definitions/1442.html

- ==**Empty Password in Configuration File:**== Using an empty string as a password is insecure.

- ==**Use of Hard-coded Password:**== The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components.

- ==**Improper Authentication:**== When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

- ==**Authentication Bypass Using an Alternate Path or Channel:**== The product requires authentication, but the product has an alternate path or channel that does not require authentication.

- ==**Authentication Bypass by Alternate Name:**== The product performs authentication based on the name of a resource being accessed, or the name of the actor performing the access, but it does not properly check all possible names for that resource or actor.

- ==**Authentication Bypass by Spoofing:**== This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.
	- ==**Reliance on IP Address for Authentication**==
	- ==**Using Rerefer Field for Authentication**==
	- ==**Reliance on Reverse DNS Resolution for a Security-Critical Action**==
	- ==**Client-Side Enforcement of Server-Side Security**==

- ==**Authentication Bypass by Capture-replay:**== A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).

- ==**Improper Certificate Validation:**== The product does not validate, or incorrectly validates, a certificate.

- ==**Improper Validation of Certificate with Host Mismatch:**== The product communicates with a host that provides a certificate, but the product does not properly ensure that the certificate is actually associated with that host.

- ==**Improper Validation of Certificate Expiration:**== A certificate expiration is not validated or is incorrectly validated, so trust may be assigned to certificates that have been abandoned due to age.

- ==**Improper Check for Certificate Revocation:**== The product does not check or incorrectly checks the revocation status of a certificate, which may cause it to use a certificate that has been compromised.

- ==**Channel Accessible by Non-Endpoint:**== The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.

- ==**Authentication Bypass by Assumed-Immutable Data:**== The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.

- ==**Incorrect Implementation of Authentication Algorithm:**== The requirements for the product dictate the use of an established authentication algorithm, but the implementation of the algorithm is incorrect.

- ==**Missing Authentication for Critical Function:**== The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

- ==**Missing Critical Steps in Authentication:**== The product implements an authentication technique, but it skips a step that weakens the technique

- ==**Authentication Bypass by Primary Weakness:**== The authentication algorithm is sound, but the implemented mechanism can be bypassed as the result of a separate weakness that is primary to the authentication error.

- ==**Improper Restriction of Excessive Authentication Attempts:**== The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.

- ==**Use of Single-factor Authentication:**== The product uses an authentication algorithm that uses a single factor (e.g., a password) in a security context that should require more than one factor.

- ==**Use of Password System for Primary Authentication:**== The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

- ==**Use of Password System for Primary Authentication:**== The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

- ==**Origin Validation Error:**== The product does not properly verify that the source of data or communication is valid.

- ==**Reliance on Reverse DNS Resolution for a Security-Critical Action:**== The product performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision, but it does not properly ensure that the IP address is truly associated with the hostname.

- ==**Session Fixation:**== Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.

- ==**Weak Password Requirements:**== The product does not require that users should have strong passwords.

- ==**Insufficient Session Expiration:**== According to WASC, "Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization."

- ==**Unverified Password Change:**== When setting a new password for a user, the product does not require knowledge of the original password, or using another form of authentication.

- ==**Weak Password Recovery Mechanism for Forgotten Password:**== The product contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak.

- ==**Use of Hard-coded Credentials:**== The product contains hard-coded credentials, such as a password or cryptographic key.

- ==**Improper Verification of Source of a Communication Channel:**== The product establishes a communication channel to handle an incoming request that has been initiated by an actor, but it does not properly verify that the request is coming from the expected origin.

- ==**Incorrectly Specified Destination in a Communication Channel:**== The product creates a communication channel to initiate an outgoing request to an actor, but it does not correctly specify the intended destination for that actor.

- ==**Weak Authentication:**== 
	- ==**Improper Resolution of Path Equivalence**==
	- ==**Not Using Password Aging**==
	- ==**Password Aging with Long Expiration**==
	- ==**Guessable CAPTCHA**==
	- ==**Use of Password Hash Instead of Password for Authentication**==
	- ==**Use of Weak Credentials**==

- ==**Use of Default Credentials:**== The product uses default credentials (such as passwords or cryptographic keys) for potentially critical functionality.

- ==**Use of Default Password:**== The product uses default passwords for potentially critical functionality.

### **CWE Category: OWASP Top 10 08: Software or Data Integrity Failures**
https://cwe.mitre.org/data/definitions/1443.html

- ==**Insufficient Verification of Data Authenticity:**== The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

- ==**Missing Support for Integrity Check:**==The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.

- ==**Untrusted Search Path:**== The product searches for critical resources using an externally-supplied search path that can point to resources that are not under the product's direct control.

- ==**Uncontrolled Search Path Element:**== The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.

- ==**Download of Code Without Integrity Check:**== The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

- ==**Deserialization of Untrusted Data:**== The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.

- ==**Embedded Malicious Code:**== The product contains code that appears to be malicious in nature.

- ==**Replicating Malicious Code (Virus or Worm):**== Replicating malicious code, including viruses and worms, will attempt to attack other systems once it has successfully compromised the target system or the product.

- ==**Reliance on Cookies without Validation and Integrity Checking:**== The product relies on the existence or values of cookies when performing security-critical operations, but it does not properly ensure that the setting is valid for the associated user.

- ==**Reliance on Cookies without Validation and Integrity Checking in a Security Decision:**== The product uses a protection mechanism that relies on the existence or values of a cookie, but it does not properly ensure that the cookie is valid for the associated user,

- ==**Inclusion of Functionality from Untrusted Control Sphere:**== The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

- ==**Inclusion of Web Functionality from an Untrusted Source:**== The product includes web functionality (such as a web widget) from another domain, which causes it to operate within the domain of the product, potentially granting total access and control of the product to the untrusted source.

- ==**Improperly Controlled Modification of Dynamically-Determined Object Attributes:**== The product receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified.

- ==**Improper Export of Android Application Components:**== The Android application exports a component for use by other applications, but does not properly restrict which applications can launch the component or access the data it contains.

### **CWE Category: OWASP Top 10 09: Logging and Alerting Failures**

- ==**Improper Output Neutralization for Logs:**== The product constructs a log message from external input, but it does not neutralize or incorrectly neutralizes special elements when the message is written to a log file.

- ==**Information Loss or Omission:**== The product does not record, or improperly records, security-relevant information that leads to an incorrect decision or hampers later analysis.

- ==**Omission of Security-relevant Information:**== The product does not record or display information that would be important for identifying the source or nature of an attack, or determining if an action is safe.

- ==**Insertion of Sensitive Information into Log File:**== The product writes sensitive information to a log file.

- ==**Insufficient Logging:**== When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

### **CWE Category: OWASP Top 10 10: Mishandling of Exceptional Conditions**

- ==**Generation of Error Message Containing Sensitive Information:**== The product generates an error message that includes sensitive information about its environment, users, or associated data.

- ==**Insertion of Sensitive Information Into Debugging Code:**== The product inserts sensitive information into debugging code, which could expose this information if the debugging code is not disabled in production.

- ==**Failure to Handle Missing Parameter:**== If too few arguments are sent to a function, the function will still pop the expected number of arguments from the stack. Potentially, a variable number of arguments could be exhausted in a function as well.

- ==**Improper Handling of Extra Parameters:**== The product does not handle or incorrectly handles when the number of parameters, fields, or arguments with the same name exceeds the expected amount.

- ==**Uncaught Exception:**== An exception is thrown from a function, but it is not caught.

- ==**Unchecked Return Value:**== The product does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions.

- ==**Improper Handling of Insufficient Privileges:**== The product does not handle or incorrectly handles when it has insufficient privileges to perform an operation, leading to resultant weaknesses.

- ==**Divide By Zero:**== The product divides a value by zero. This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected. It frequently occurs in calculations involving physical dimensions such as size, length, width, and height.

- ==**Detection of Error Condition Without Action:**== The product detects a specific error, but takes no actions to handle the error.

- ==**Unchecked Error Condition:**== Ignoring exceptions and other error conditions may allow an attacker to induce unexpected behavior unnoticed.

- ==**Unexpected Status Code or Return Value:**== The product does not properly check when a function or operation returns a value that is legitimate for the function, but is not expected by the product.

- ==**Declaration of Catch for Generic Exception:**== Catching overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.

- ==**Declaration of Throws for Generic Exception:**== The product throws or raises an overly broad exceptions that can hide important details and produce inappropriate responses to certain conditions.

- ==**Improper Cleanup on Thrown Exception:**== The product does not clean up its state or incorrectly cleans up its state when an exception is thrown, leading to unexpected state or control flow.

- ==**Null Pointer Dereference:**== The product dereferences a pointer that it expects to be valid but is NULL.

- ==**Missing Default Case in Multiple Condition Expression:**== The code does not have a default case in an expression with multiple conditions, such as a switch statement.

- ==**Omitted Break Statement in Switch:**== The product omits a break statement within a switch or similar construct, causing code associated with multiple conditions to execute. This can cause problems when the programmer only intended to execute code associated with one condition.

- ==**Server-generated Error Message Containing Sensitive Information:**== Certain conditions, such as network failure, will cause a server error message to be displayed.

- ==**Not Failing Securely ('Failing Open'):**== When the product encounters an error condition or failure, its design requires it to fall back to a state that is less secure than other options that are available, such as selecting the weakest encryption algorithm or using the most permissive access control restrictions.

- ==**Improper Check for Handling of Exceptional Conditions:**== The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product.

- ==**Improper Check for Unusual or Exceptional Conditions:**== The product does not check or incorrectly checks for unusual or exceptional conditions that are not expected to occur frequently during day to day operation of the product.

- ==**Improper Handling of Exceptional Conditions:**== The product does not handle or incorrectly handles an exceptional condition.

- ==**Missing Custom Error Page:**== The product does not return custom error pages to the user, possibly exposing sensitive information.
