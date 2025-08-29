package com.cloudcred.model;


// This class represents a single detected leak or suspicious credential in a file.
// It stores the file path, line number, suspicious content, and severity level.
public class Finding {

    // Severity levels for a finding (HIGH, MEDIUM, LOW)
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

    // Get the file path where the leak was found
    public String getFilePath() {
        return filePath;
    }

    // Get the line number of the leak
    public int getLineNumber() {
        return lineNumber;
    }

    // Get the suspicious line content
    public String getSuspiciousLine() {
        return suspiciousLine;
    }

    // Get the severity of the finding
    public Severity getSeverity() {
        return severity;
    }

    // String representation for reporting and alerts
    @Override
    public String toString() {
        return "[" + severity + "] " + filePath + " (line " + lineNumber + "):\n" + suspiciousLine;
    }
}
