package com.cloudcred;

import com.cloudcred.alert.AlertService;
import com.cloudcred.fixer.Fixer;
import com.cloudcred.model.Finding;
import com.cloudcred.model.ScanConfig;
import com.cloudcred.report.ReportWriter;
import com.cloudcred.scanner.FileScanner;
import com.cloudcred.scanner.S3FileScanner;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;

import java.util.*;
import java.util.stream.Collectors;
import java.io.File;

public class Main {
    /**
     * Entry point for CloudCred Shield.
     * Handles interactive user input, configures scan, and coordinates scanning, alerting, reporting, and remediation.
     */
    public static void main(String[] args) {
        System.out.println(">>\nWelcome to CloudCred Shield - Your Security Scanner for Local and AWS S3 Files!");
        System.out.println("(You can type 'exit' at any time to quit)");
        System.out.println("=======================================================================\n");

        Scanner scanner = new Scanner(System.in);
        ScanConfig config = new ScanConfig();

        // Prompt user for minimum severity level (LOW/MEDIUM/HIGH)
        while (true) {
            System.out.print("Enter minimum severity level (LOW/MEDIUM/HIGH) [default: LOW]: ");
            String sevInput = scanner.nextLine().trim();
            if (sevInput.equalsIgnoreCase("exit")) System.exit(0);
            if (sevInput.isEmpty()) break;
            try {
                config.minSeverity = Finding.Severity.valueOf(sevInput.toUpperCase());
                break;
            } catch (IllegalArgumentException e) {
                System.out.println("Invalid severity level. Please enter LOW, MEDIUM, or HIGH.");
            }
        }

        // Ask if user wants to scan local files
        System.out.print("Do you want to scan local directory files? (yes/no) [default: yes]: ");
        String localChoice = scanner.nextLine().trim().toLowerCase();
        if (localChoice.equals("exit")) System.exit(0);
        boolean scanLocal = localChoice.isEmpty() || localChoice.equals("yes");

        // If scanning local, ask for directory path
        if (scanLocal) {
            System.out.print("Enter directory path to scan (or press Enter to use current directory): ");
            String pathInput = scanner.nextLine().trim();
            if (pathInput.equalsIgnoreCase("exit")) System.exit(0);
            config.path = pathInput.isEmpty() ? "." : pathInput;
        }

        // Ask if user wants to scan AWS S3
        System.out.print("Do you want to scan AWS S3? (yes/no) [default: no]: ");
        String s3Choice = scanner.nextLine().trim().toLowerCase();
        if (s3Choice.equals("exit")) System.exit(0);
        boolean scanS3 = s3Choice.equals("yes");

        if (scanS3) {
            try {
                // List available S3 buckets
                S3Client s3Client = S3Client.create();
                ListBucketsResponse bucketsResp = s3Client.listBuckets(ListBucketsRequest.builder().build());
                List<Bucket> buckets = bucketsResp.buckets();

                if (buckets.isEmpty()) {
                    System.out.println("No buckets found in your AWS profile.");
                    scanS3 = false;
                } else {
                    System.out.println("\nAvailable Buckets:");
                    for (int i = 0; i < buckets.size(); i++) {
                        System.out.println("  " + (i + 1) + ". " + buckets.get(i).name());
                    }

                    // Prompt user to select buckets to scan
                    System.out.print("Enter bucket numbers to scan (comma-separated) or 'all' to scan all [default: all]: ");
                    String bucketInput = scanner.nextLine().trim().toLowerCase();
                    if (bucketInput.equals("exit")) System.exit(0);

                    List<String> selected;
                    if (bucketInput.isEmpty() || bucketInput.equals("all")) {
                        selected = buckets.stream().map(Bucket::name).collect(Collectors.toList());
                    } else {
                        selected = new ArrayList<>();
                        for (String indexStr : bucketInput.split(",")) {
                            try {
                                int index = Integer.parseInt(indexStr.trim()) - 1;
                                if (index >= 0 && index < buckets.size()) {
                                    selected.add(buckets.get(index).name());
                                }
                            } catch (NumberFormatException ignored) {}
                        }
                    }

                    if (selected.isEmpty()) {
                        System.out.println("No valid buckets selected. Skipping S3 scan.");
                        scanS3 = false;
                    } else {
                        config.s3Buckets = selected;
                        System.out.println("Note: Scanning S3 may take time depending on the size of the files.");
                    }
                }
            } catch (Exception e) {
                System.out.println("Failed to retrieve S3 buckets: " + e.getMessage());
                scanS3 = false;
            }
        }

        List<Finding> allFindings = new ArrayList<>();

        // Scan local files if requested
        if (scanLocal) {
            System.out.println("\n===> Scanning local directory...");
            FileScanner fileScanner = new FileScanner(config);
            List<Finding> localFindings = fileScanner.scanDirectory(config.path);
            System.out.println("Local findings: " + localFindings.size());
            allFindings.addAll(localFindings);
        }

        // Scan selected S3 buckets if requested
        if (scanS3 && config.s3Buckets != null) {
            System.out.println("\n===> Scanning selected S3 buckets...");
            S3FileScanner s3Scanner = new S3FileScanner(config);
            List<Finding> s3Findings = s3Scanner.scanS3();
            System.out.println("S3 findings: " + s3Findings.size());
            allFindings.addAll(s3Findings);
        }

        // Generate alerts for findings above minimum severity
        System.out.println("\n===> Generating alerts and report...");
        AlertService alertService = new AlertService();
        for (Finding finding : allFindings) {
            if (finding.getSeverity().ordinal() >= config.minSeverity.ordinal()) {
                alertService.sendAlert(finding);
            }
        }

        // Write scan report and handle remediation
        new ReportWriter().writeReport(allFindings, "scan_report.txt", config);
        new Fixer().handleFindings(allFindings);

        System.out.println("\nDone. Total findings: " + allFindings.size());

        // Ask user if they want to open the scan report
        System.out.print("\nWould you like to open the scan report now? (yes/no): ");
        String openReport = scanner.nextLine().trim().toLowerCase();
        if (openReport.equals("exit")) System.exit(0);
        if (openReport.equals("yes")) {
            try {
                java.awt.Desktop.getDesktop().open(new File("scan_report.txt"));
            } catch (Exception e) {
                System.out.println("Could not open report: " + e.getMessage());
            }
        }
    }
}
