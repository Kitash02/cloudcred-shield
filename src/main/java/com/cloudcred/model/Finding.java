package com.cloudcred.model;

public class Finding {
    public enum Severity { HIGH, MEDIUM, LOW }

    private final String filePath;
    private final int lineNumber;
    private final String suspiciousLine;
    private final Severity severity;

    public Finding(String filePath, int lineNumber, String suspiciousLine, Severity severity) {
        this.filePath = filePath;
        this.lineNumber = lineNumber;
        this.suspiciousLine = suspiciousLine;
        this.severity = severity;
    }

    public String getFilePath() { return filePath; }
    public int getLineNumber() { return lineNumber; }
    public String getSuspiciousLine() { return suspiciousLine; }
    public Severity getSeverity() { return severity; }

    @Override
    public String toString() {
        return "[" + severity + "] " + filePath + " (line " + lineNumber + "):\n" + suspiciousLine;
    }
}
