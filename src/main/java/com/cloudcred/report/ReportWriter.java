package com.cloudcred.report;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;
import com.cloudcred.model.ScanConfig;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;


// This class is responsible for generating a human-readable scan report.
// It summarizes findings and writes details to a file for later review.
public class ReportWriter {

    /**
     * Writes a summary and details of findings to the given file path.
     * @param findings   List of findings collected from the scan.
     * @param outputPath Path to save the report.
     * @param config     Configuration used for the scan.
     */
    public void writeReport(List<Finding> findings, String outputPath, ScanConfig config) {
        // Count findings by severity for summary
        Map<Severity, Long> countsBySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            countsBySeverity.put(s, findings.stream().filter(f -> f.getSeverity() == s).count());
        }

        int totalFindings = findings.size();
        int highCount = countsBySeverity.getOrDefault(Severity.HIGH, 0L).intValue();
        int mediumCount = countsBySeverity.getOrDefault(Severity.MEDIUM, 0L).intValue();
        int lowCount = countsBySeverity.getOrDefault(Severity.LOW, 0L).intValue();

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath, false))) {
            // Write report header and scan configuration
            writer.write("CloudCred Shield - Scan Report\n");
            writer.write("====================================\n");
            writer.write("Date: " + timestamp + "\n");
            writer.write("Directory Scanned: " + config.path + "\n");
            writer.write("Minimum Severity: " + config.minSeverity + "\n");
            writer.write("File Types Included: " + String.join(", ", config.allowedExtensions) + "\n\n");

            // Write summary section
            writer.write("Summary:\n");
            writer.write("--------\n");
            writer.write("Total Findings: " + totalFindings + "\n");
            writer.write("  - HIGH: " + highCount + "\n");
            writer.write("  - MEDIUM: " + mediumCount + "\n");
            writer.write("  - LOW: " + lowCount + "\n\n");

            // Write details for each finding
            if (totalFindings > 0) {
                writer.write("Findings:\n");
                writer.write("---------\n\n");
                for (Finding finding : findings) {
                    writer.write("[" + finding.getSeverity() + "] " + finding.getFilePath() +
                            " (line " + finding.getLineNumber() + "):\n" +
                            finding.getSuspiciousLine() + "\n\n");
                }
            } else {
                writer.write("No findings detected. All clear!\n");
            }

            System.out.println("Detailed scan report saved to: " + outputPath);
        } catch (IOException e) {
            System.err.println("Failed to write scan report: " + e.getMessage());
        }
    }
}
