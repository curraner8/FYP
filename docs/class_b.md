# Class B

---

### B1. Dangerous Eval

The `eval()` function executes a string as code. Even if not directly linked to user input its presence is a massive security risk.

**Pattern:**
```
`(?i)^[^#//]*\beval\s*\(`
```

- Looks for the `eval(` keyword at the start of a line. Removes comment symbols to reduce false positives.

---

### B2. OS Command Execution

Using APIs that reach out to the operating system to run commands. This is often unnecessary and prone to exploitation.

**Pattern:**
```
`(?i)\b(exec|system|popen|os\.system|subprocess\.call|subprocess\.run|Runtime\.exec|ProcessBuilder)\s*\(`
```

- Uses a word-boundary search (`\b`) to find a list of known command execution functions.

---

### B3. Insecure Deserialization - Pickle

Python's `pickle` module can execute arbitrary code during the process of "unpickling" data.

**Pattern:**
```
`(?i)pickle\.loads?\s*\(`
```

- It looks specifically for `pickle.load` or `pickle.loads`.

---

### B4. Java Deserialization

Similar to Pickle, Java's deserialization is vulnerable and can lead to remote code execution.

**Pattern:**
```
`(?i)new\s+ObjectInputStream|ObjectInputStream\.readObject`
```

- Scans for `ObjectInputStream` or calls to `readObject()`, which are risky ways Java handles serialized objects.

---

### B5. Unsafe YAML

Some YAML parsers can instantiate any Python or Java object defined in the YAML file, leading to code execution.

**Pattern:**
```
`(?i)(` +
`yaml\.(load|full_load)\s*\(|` +
`Yaml\.(load|loadAll)\s*\(` +
`)`
```

- Flags the use of generic `.load()` or `full.load()` methods which are less restrictive than the recommended `safe_load()`.

---

### B6. Shell Injection Risk

In Python's `subprocess` module, setting `shell=True` invokes the system shell which makes the application vulnerable to command injection if any part of the string is untrusted.

**Pattern:**
```
`(?is)subprocess\.(call|run|Popen)\s*\([^)]{0,300}shell\s*=\s*True`
```

- Uses a single line flag to look for `subprocess` calls that contain the specific `shell=True` parameter within the next 300 characters.

---

### B7. Weak Crypto Hash

Algorithms like MD5 and SHA-1 are mathematically broken and vulnerable. They should not be used for security.

**Pattern:**
```
`(?i)(` +
`hashlib\.(md5|sha1)\s*\(|` +
`\bmd5\s*\(|\bsha1\s*\(|` +
`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']|` +
`crypto\.createHash\s*\(\s*["'](md5|sha1)["']|` +
`md5\.New\(\)|sha1\.New\(\)` +
`)`
```

- Searches for common library calls that explicitly request MD5 or SHA-1 as the hashing algorithms.

---

### B8. Insecure Random Number Generator

Standard "Random" functions like `Math.Random()` are pseudo-random and predictable, making them unsuitable for generating password, tokens, or keys.

**Pattern:**
```
`(?i)Math\.random\s*\(|random\.randint|random\.random\s*\(|java\.util\.Random|rand\(\)`
```

- It identifies calls to non-cryptographic random generators.

---

### B9. XXE Risk / Insecure XML Parser

XML External Entity attacks occur when an XML parser processes external entity references, which can leak local files or scan internal networks.

**Pattern:**
```
`(?i)(` +
`DocumentBuilderFactory\.newInstance\s*\(|` +
`SAXParserFactory\.newInstance\s*\(|` +
`new\s+XMLReader|` +
`lxml\.etree\.(parse|fromstring)\s*\(|` +
`xml\.etree\.ElementTree\.(parse|fromstring)\s*\(|` +
`XmlDocument\s*\(\s*\)|` +
`new\s+XmlTextReader\s*\(` +
`)`
```

- Detects the initialization of common XML parsers. Since these can be configured safely, they are given a medium confidence.
