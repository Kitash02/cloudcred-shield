package com.cloudcred.scanner;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;
import com.cloudcred.model.ScanConfig;

import java.io.*;
import java.util.*;
import java.util.regex.*;

/**
 * Scans local files and directories for sensitive data patterns.
 */
public class FileScanner {
    private final ScanConfig config;

    public FileScanner(ScanConfig config) {
        this.config = config;
    }

    // High risk patterns (e.g., AWS keys)
    private static final Pattern HIGH_PATTERN = Pattern.compile(
        "(AKIA[0-9A-Z]{16})|(aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40})"
    );

    // Medium risk patterns (e.g., tokens, secrets)
    private static final Pattern MEDIUM_PATTERN = Pattern.compile(
        "(?i)(secret|token|key).{0,20}[=:]?\\s*[A-Za-z0-9/+=]{30,60}"
    );

    // Low risk: general long strings that could be secrets
    private static final Pattern LOW_PATTERN = Pattern.compile(
        "\\b[A-Za-z0-9/+=]{40}\\b"
    );

    /**
     * Scans the directory recursively for matching files and sensitive content.
     *
     * @param path Root directory path to scan.
     * @return List of detected findings.
     */
    public List<Finding> scanDirectory(String path) {
        List<Finding> findings = new ArrayList<>();
        File root = new File(path);
        scanRecursive(root, findings);
        return findings;
    }

    private void scanRecursive(File file, List<Finding> findings) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File f : children) {
                    scanRecursive(f, findings);
                }
            }
        } else if (file.isFile() && file.canRead() && shouldScan(file)) {
            scanFile(file, findings);
        }
    }

    private void scanFile(File file, List<Finding> findings) {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNum = 0;

            while ((line = reader.readLine()) != null) {
                lineNum++;

                if (HIGH_PATTERN.matcher(line).find()) {
                    findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.HIGH));
                } else if (MEDIUM_PATTERN.matcher(line).find()) {
                    findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.MEDIUM));
                } else if (LOW_PATTERN.matcher(line).find()) {
                    findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.LOW));
                } else if (line.contains("=") || line.contains(":")) {
                    checkKeyValuePattern(file.getPath(), line, lineNum, findings);
                }
            }

        } catch (IOException e) {
            System.err.println("Error reading file: " + file.getPath() + " - " + e.getMessage());
        }
    }

    private void checkKeyValuePattern(String filePath, String line, int lineNum, List<Finding> findings) {
        String[] parts = line.split("[:=]", 2);
        if (parts.length != 2) return;

        String key = parts[0].trim().replaceAll("\"", "");
        String value = parts[1].trim().replaceAll("[\",]", "");

        if (isSuspiciousKey(key) && isSuspiciousValue(value)) {
            findings.add(new Finding(filePath, lineNum, line.trim(), Severity.MEDIUM));
        }
    }

    private boolean shouldScan(File file) {
        String name = file.getName();

        // Skip ignored filenames
        if (config.ignoreFilenames.contains(name)) return false;

        int dotIndex = name.lastIndexOf('.');
        if (dotIndex == -1) return false;

        String ext = name.substring(dotIndex + 1).toLowerCase();
        return config.allowedExtensions.contains(ext);
    }

    private boolean isSuspiciousKey(String key) {
        String lower = key.toLowerCase();
        return lower.contains("secret") ||
               lower.contains("token") ||
               lower.contains("key") ||
               lower.contains("password");
    }

    private boolean isSuspiciousValue(String value) {
        return value.length() >= 30 && value.matches("^[A-Za-z0-9/+=]{30,}$");
    }
}
