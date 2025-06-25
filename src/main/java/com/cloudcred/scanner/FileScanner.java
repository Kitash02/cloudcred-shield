package com.cloudcred.scanner;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;
import com.cloudcred.model.ScanConfig;

import java.io.*;
import java.util.*;
import java.util.regex.*;


public class FileScanner {
    private final ScanConfig config;

    public FileScanner(ScanConfig config) {
        this.config = config;
    }

    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(
            Arrays.asList("env", "json", "yml", "yaml", "py", "java", "txt")
    );

    private static final Pattern HIGH_PATTERN = Pattern.compile(
            "(AKIA[0-9A-Z]{16})|(aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40})"
    );

    private static final Pattern MEDIUM_PATTERN = Pattern.compile(
            "(?i)(secret|token|key).{0,20}[=:]?\\s*[A-Za-z0-9/+=]{30,60}"
    );

    private static final Pattern LOW_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9/+=]{40}\\b"
    );

    public List<Finding> scanDirectory(String path) {
        List<Finding> findings = new ArrayList<>();
        File root = new File(path);
        scanRecursive(root, findings);
        return findings;
    }

    private void scanRecursive(File file, List<Finding> findings) {
        if (file.isDirectory()) {
            for (File f : Objects.requireNonNull(file.listFiles())) {
                scanRecursive(f, findings);
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
                    // Simple ENV or JSON pattern check
                    String[] parts = line.split("[:=]", 2);
                    if (parts.length == 2) {
                        String key = parts[0].trim().replaceAll("\"", "");
                        String value = parts[1].trim().replaceAll("[\",]", "");
                        if (isSuspiciousKey(key) && isSuspiciousValue(value)) {
                            findings.add(new Finding(file.getPath(), lineNum, line.trim(), Severity.MEDIUM));
                        }
                    }
                }

            }
        } catch (IOException ignored) {}
    }

    private boolean shouldScan(File file) {
        String name = file.getName();

        // Ignore specific filenames
        if (config.ignoreFilenames.contains(name)) {
            return false;
        }

        // Extension filtering
        int dotIndex = name.lastIndexOf('.');
        if (dotIndex == -1) return false;

        String ext = name.substring(dotIndex + 1).toLowerCase();
        return config.allowedExtensions.contains(ext);
    }



    private boolean isSuspiciousKey(String key) {
        String lowerKey = key.toLowerCase();
        return lowerKey.contains("secret") || lowerKey.contains("token") ||
                lowerKey.contains("key") || lowerKey.contains("password");
    }

    private boolean isSuspiciousValue(String value) {
        return value.length() >= 30 && value.matches("^[A-Za-z0-9/+=]{30,}$");
    }

}
