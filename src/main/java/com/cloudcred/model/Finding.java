package com.cloudcred.model;

/**
 * Represents a single finding (potential credential exposure) in a file.
 */
public class Finding {

    /**
     * Severity levels for a finding.
     */
    public enum Severity {
        HIGH,
        MEDIUM,
        LOW
    }

    private final String filePath;
    private final int lineNumber;
    private final String suspiciousLine;
    private final Severity severity;

    /**
     * Constructs a Finding object.
     *
     * @param filePath       Path to the file containing the finding.
     * @param lineNumber     Line number where the suspicious content was found.
     * @param suspiciousLine The actual line content.
     * @param severity       Severity level of the finding.
     */
    public Finding(String filePath, int lineNumber, String suspiciousLine, Severity severity) {
        this.filePath = filePath;
        this.lineNumber = lineNumber;
        this.suspiciousLine = suspiciousLine;
        this.severity = severity;
    }

    public String getFilePath() {
        return filePath;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public String getSuspiciousLine() {
        return suspiciousLine;
    }

    public Severity getSeverity() {
        return severity;
    }

    @Override
    public String toString() {
        return "[" + severity + "] " + filePath + " (line " + lineNumber + "):\n" + suspiciousLine;
    }
}
