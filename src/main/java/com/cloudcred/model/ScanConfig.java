package com.cloudcred.model;

import com.cloudcred.model.Finding.Severity;

import java.util.*;

public class ScanConfig {
    public String path = ".";
    public Severity minSeverity = Severity.LOW;
    public Set<String> allowedExtensions = new HashSet<>(Arrays.asList(
            "env", "json", "yml", "yaml", "py", "java", "txt"
    ));

    public Set<String> ignoreFilenames = new HashSet<>(Arrays.asList(
            "scan_report.txt"
    ));

    public boolean overwriteReport = true;
    public String emailAddress = null;

    public String s3Bucket = null;
    public String s3Prefix = "";

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
                config.s3Bucket = arg.substring("--s3-bucket=".length()).trim();
            } else if (arg.startsWith("--s3-prefix=")) {
                config.s3Prefix = arg.substring("--s3-prefix=".length()).trim();
            }
        }

        return config;
    }
}
