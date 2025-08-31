# CloudCred Shield

CloudCred Shield is a lightweight and flexible CLI-based security scanner for detecting, reporting, and remediating exposed credentials or secrets in both local file systems and AWS S3 buckets.

---

## Purpose

This tool was built for dual purposes:

1. **Security Auditing and Remediation**  
   It helps detect sensitive strings like AWS access keys, secrets, or other hardcoded tokens within files. Once detected, the user can choose to either redact them, mask them with a placeholder, or leave them as is.

2. **Educational and Awareness Tool**  
   It is designed to increase security awareness among developers and IT staff. It encourages good practices by showing examples of exposed credentials and how to deal with them, helping reduce credential leaks in version control systems and shared environments.

---

## How it works

- Scans current work directory and/or AWS S3 buckets for sensitive content
- Uses configurable thresholds (LOW / MEDIUM / HIGH)
- Allows interactive handling of findings: redaction via hashing, replacement with placeholder, or ignoring
- Generates a detailed report (`scan_report.txt`)
- Supports automated or manual environments

---

## Requirements

- Java 17 or higher
- Maven (for dependency resolution and packaging)
- AWS credentials properly configured for the current environment (for S3 scanning)

---


## Pros and Cons

### Pros
- Can scan, redact, and change AWS S3 files directly from the CLI
- Flexible remediation options: redact, replace, or ignore leaks with user-friendly prompts
- Interactive and easy to use for both auditing and education
- Generates detailed reports for review and compliance
- Modular design makes it easy to extend detection patterns and file types

### Cons
- By default, scans only the `test-files` directory; scanning the entire local filesystem is not supported yet
- Does not support all possible file types or credential formats (can be expanded)
- Currently focuses on AWS S3 API keys and common patterns, not all credential types
- No automated CI/CD integration or scheduling (manual run only)
- No support for encrypted or binary files

###how to run

### 1. Clone and build the project:
```bash
git clone https://github.com/your-repo/cloudcred-shield.git
cd cloudcred-shield
mvn clean package
```
> This will generate the executable `.jar` file under the `target/` directory.

### 2. Run the scanner interactively:
```bash
java -jar target/cloudcred-shield-1.0-SNAPSHOT.jar
```
You will be prompted with interactive questions such as:
- Minimum severity level (LOW, MEDIUM, HIGH)
- Whether to scan local files and the directory path (defaults to current folder)
- Whether to scan AWS S3, with the ability to select specific buckets
- File extensions to include (e.g., `.json`, `.txt`, etc.)
- Whether to open the report after scan completion

---
