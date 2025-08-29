package com.cloudcred.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.cloudcred.model.Finding.Severity;


// This class holds all configuration options for a scan session.
// It controls what files are scanned, what is ignored, and other scan settings.
public class ScanConfig {
    // Local path to scan
    public String path = ".";
    // Minimum severity level to report
    public Severity minSeverity = Severity.LOW;
    // List of file extensions to scan for leaks
    public Set<String> allowedExtensions = new HashSet<>(Arrays.asList(
        "json", "yml", "yaml", "py", "java", "txt",
        "ini", "conf", "xml", "properties",
        "sh", "bat", "ps1",
        "rb", "js", "ts", "go", "php", "c", "cpp",
        "dockerfile", "compose",
        "csv", "log"
    ));

    // List of filenames to ignore during scan
    public Set<String> ignoreFilenames = new HashSet<>(Arrays.asList(
        "scan_report.txt", "env", "pem", "key", "crt", "p12", "jks", "asc", "vault", "secrets", "credentials", "dockerconfigjson", "aws/credentials", "gpg", "pfx"
    ));

    // Whether to overwrite the report file
    public boolean overwriteReport = true;
    // Optional email address for alerts
    public String emailAddress = null;

    // Optional prefix for S3 scanning
    public String s3Prefix = "";

    // List of S3 buckets to scan
    public List<String> s3Buckets = new ArrayList<>();

    /**
     * Legacy support for command-line args (optional if using interactive mode)
     * Allows configuration via command-line arguments.
     */
    public static ScanConfig fromArgs(String[] args) {
        ScanConfig config = new ScanConfig();

        for (String arg : args) {
            if (arg.startsWith("--path=")) {
                config.path = arg.substring("--path=".length());
            } else if (arg.startsWith("--min-severity=")) {
                try {
                    config.minSeverity = Severity.valueOf(
                            arg.substring("--min-severity=".length()).toUpperCase()
                    );
                } catch (IllegalArgumentException e) {
                    System.out.println("Invalid severity level. Using default: LOW");
                }
            } else if (arg.startsWith("--ext=")) {
                String[] exts = arg.substring("--ext=".length()).split(",");
                config.allowedExtensions = new HashSet<>();
                for (String ext : exts) {
                    config.allowedExtensions.add(ext.trim().toLowerCase());
                }
            } else if (arg.startsWith("--ignore=")) {
                String[] names = arg.substring("--ignore=".length()).split(",");
                config.ignoreFilenames = new HashSet<>();
                for (String name : names) {
                    config.ignoreFilenames.add(name.trim());
                }
            } else if (arg.equals("--no-overwrite-report")) {
                config.overwriteReport = false;
            } else if (arg.startsWith("--email=")) {
                config.emailAddress = arg.substring("--email=".length()).trim();
            } else if (arg.startsWith("--s3-bucket=")) {
                config.s3Buckets.add(arg.substring("--s3-bucket=".length()).trim());
            } else if (arg.startsWith("--s3-prefix=")) {
                config.s3Prefix = arg.substring("--s3-prefix=".length()).trim();
            }
        }

        return config;
    }
}
