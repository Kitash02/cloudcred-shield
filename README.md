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

- Scans local directories and/or AWS S3 buckets for sensitive content
- Uses configurable thresholds (LOW / MEDIUM / HIGH)
- Allows interactive handling of findings: redaction via hashing, replacement with placeholder, or ignoring
- Generates a detailed report (`scan_report.txt`)
- Supports automated or manual environments

---

## Requirements

- Java 17 or higher
- Maven (for dependency resolution and packaging)
- AWS credentials properly configured for the current environment (for S3 scanning)

### Why Maven?

Maven is required to:
- Download and manage dependencies (such as AWS SDK)
- Package the code into a single executable `.jar` file
- Ensure compatibility with libraries and plugins used in the project

You can optionally replace Maven with Gradle, but this project is Maven-based by default.

---

## How to Run

### 1. Clone and build the project:
```bash
git clone https://github.com/your-repo/cloudcred-shield.git
cd cloudcred-shield
mvn clean package
