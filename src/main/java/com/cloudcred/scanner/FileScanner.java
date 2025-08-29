package com.cloudcred.scanner;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;
import com.cloudcred.model.ScanConfig;

import java.io.*;
import java.util.*;
import java.util.regex.*;


/**
 * FileScanner scans local files and directories for sensitive credential leaks.
 * It uses regex patterns and key-value heuristics to classify findings by severity.
 */
public class FileScanner {
    // Configuration for scan (extensions, ignore list, etc.)
    private final ScanConfig config;

    /**
     * Constructor for FileScanner.
     * @param config ScanConfig object with scan settings.
     */
    public FileScanner(ScanConfig config) {
        this.config = config;
    }

    // Regex for high risk credentials (AWS keys, secrets)
    private static final Pattern HIGH_PATTERN = Pattern.compile(
        "(AKIA[0-9A-Z]{16})|(aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40})"
    );

    // Regex for medium risk credentials (tokens, secrets, keys)
    private static final Pattern MEDIUM_PATTERN = Pattern.compile(
        "(?i)(secret|token|key).{0,20}[=:]?\\s*[A-Za-z0-9/+=]{30,60}"
    );

    // Regex for low risk: long random strings that could be secrets
    private static final Pattern LOW_PATTERN = Pattern.compile(
        "\\b[A-Za-z0-9/+=]{40}\\b"
    );

    /**
     * Scans the directory recursively for files and sensitive content.
     * @param path Root directory path to scan.
     * @return List of detected findings.
     */
    public List<Finding> scanDirectory(String path) {
        List<Finding> findings = new ArrayList<>();
        File root = new File(path);
        scanRecursive(root, findings);
        return findings;
    }

    /**
     * Recursively scans files and subdirectories.
     * @param file File or directory to scan.
     * @param findings List to collect findings.
     */
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

    /**
     * Scans a single file for sensitive patterns.
     * @param file File to scan.
     * @param findings List to collect findings.
     */
    private void scanFile(File file, List<Finding> findings) {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNum = 0;

            while ((line = reader.readLine()) != null) {
                lineNum++;

                // Check for high, medium, and low severity patterns
                if (HIGH_PATTERN.matcher(line).find()) {
                    findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.HIGH));
                } else if (MEDIUM_PATTERN.matcher(line).find()) {
                    findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.MEDIUM));
                } else if (LOW_PATTERN.matcher(line).find()) {
                    findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.LOW));
                } else if (line.contains("=") || line.contains(":")) {
                    // Heuristic: check key-value pairs for suspicious keys/values
                    checkKeyValuePattern(file.getPath(), line, lineNum, findings);
                }
            }

        } catch (IOException e) {
            System.err.println("Error reading file: " + file.getPath() + " - " + e.getMessage());
        }
    }

    /**
     * Checks key-value pairs for suspicious keys and values.
     * @param filePath Path of the file.
     * @param line Line content.
     * @param lineNum Line number.
     * @param findings List to collect findings.
     */
    private void checkKeyValuePattern(String filePath, String line, int lineNum, List<Finding> findings) {
        String[] parts = line.split("[:=]", 2);
        if (parts.length != 2) return;

        String key = parts[0].trim().replaceAll("\"", "");
        String value = parts[1].trim().replaceAll("[\",]", "");

        // If key and value are suspicious, classify as medium severity
        if (isSuspiciousKey(key) && isSuspiciousValue(value)) {
            findings.add(new Finding(filePath, lineNum, line.trim(), Severity.MEDIUM));
        }
    }

    /**
     * Determines if a file should be scanned based on extension and ignore list.
     * @param file File to check.
     * @return true if file should be scanned.
     */
    private boolean shouldScan(File file) {
        String name = file.getName();

        // Skip ignored filenames
        if (config.ignoreFilenames.contains(name)) return false;

        int dotIndex = name.lastIndexOf('.');
        if (dotIndex == -1) return false;

        String ext = name.substring(dotIndex + 1).toLowerCase();
        return config.allowedExtensions.contains(ext);
    }

    /**
     * Checks if a key is suspicious (e.g., secret, token, key, password).
     * @param key Key string.
     * @return true if key is suspicious.
     */
    private boolean isSuspiciousKey(String key) {
        String lower = key.toLowerCase();
        return lower.contains("secret") ||
               lower.contains("token") ||
               lower.contains("key") ||
               lower.contains("password");
    }

    /**
     * Checks if a value is suspicious (long random string).
     * @param value Value string.
     * @return true if value is suspicious.
     */
    private boolean isSuspiciousValue(String value) {
        return value.length() >= 30 && value.matches("^[A-Za-z0-9/+=]{30,}$");
    }
}
