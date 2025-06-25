package com.cloudcred;

import com.cloudcred.alert.AlertService;
import com.cloudcred.fixer.Fixer;
import com.cloudcred.model.Finding;
import com.cloudcred.model.ScanConfig;
import com.cloudcred.report.ReportWriter;
import com.cloudcred.scanner.FileScanner;
import com.cloudcred.scanner.S3FileScanner;

import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        ScanConfig config = ScanConfig.fromArgs(args);

        List<Finding> allFindings = new ArrayList<>();

        // Local scan
        FileScanner fileScanner = new FileScanner(config);
        List<Finding> localFindings = fileScanner.scanDirectory(config.path);
        allFindings.addAll(localFindings);

        // S3 scan
        if (config.s3Bucket != null && !config.s3Bucket.isEmpty()) {
            S3FileScanner s3Scanner = new S3FileScanner(config);
            List<Finding> s3Findings = s3Scanner.scanS3();
            allFindings.addAll(s3Findings);
        }

        // Alerts and report
        for (Finding finding : allFindings) {
            if (finding.getSeverity().ordinal() >= config.minSeverity.ordinal()) {
                new AlertService().sendAlert(finding);
            }
        }

        new ReportWriter().writeReport(allFindings, "scan_report.txt", config);
        new Fixer().handleFindings(allFindings);
    }
}
