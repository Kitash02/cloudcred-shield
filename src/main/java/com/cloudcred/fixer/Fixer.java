package com.cloudcred.fixer;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Fixer {

    public void handleFindings(List<Finding> findings) {
        if (findings.isEmpty()) {
            return;
        }

        Map<String, List<Finding>> groupedByFile = new HashMap<>();
        for (Finding finding : findings) {
            groupedByFile
                    .computeIfAbsent(finding.getFilePath(), k -> new ArrayList<>())
                    .add(finding);
        }

        for (Map.Entry<String, List<Finding>> entry : groupedByFile.entrySet()) {
            String filePath = entry.getKey();
            List<Finding> fileFindings = entry.getValue();

            try {
                List<String> originalLines = new ArrayList<>();
                try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        originalLines.add(line);
                    }
                }

                boolean[] shouldRedact = new boolean[originalLines.size()];
                boolean needsUserInput = false;

                for (Finding finding : fileFindings) {
                    int idx = finding.getLineNumber() - 1;
                    if (finding.getSeverity() == Severity.HIGH) {
                        shouldRedact[idx] = true;
                    } else if (finding.getSeverity() == Severity.MEDIUM) {
                        needsUserInput = true;
                    }
                }

                if (needsUserInput) {
                    System.out.println("Potential medium-risk credentials found in file: " + filePath);
                    System.out.print("Do you want to redact them? Type 'yes' to confirm: ");
                    Scanner scanner = new Scanner(System.in);
                    String input = scanner.nextLine();
                    if ("yes".equalsIgnoreCase(input.trim())) {
                        for (Finding finding : fileFindings) {
                            if (finding.getSeverity() == Severity.MEDIUM) {
                                shouldRedact[finding.getLineNumber() - 1] = true;
                            }
                        }
                    }
                }

                try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
                    for (int i = 0; i < originalLines.size(); i++) {
                        if (shouldRedact[i]) {
                            String originalLine = originalLines.get(i);
                            String hash = sha256(originalLine);
                            writer.write("[REDACTED_SHA256:" + hash + "]");
                        } else {
                            writer.write(originalLines.get(i));
                        }
                        writer.newLine();
                    }
                }

                System.out.println("File processed: " + filePath);
            } catch (IOException e) {
                System.out.println("Error processing file: " + filePath + " - " + e.getMessage());
            }
        }
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
            for (byte b : encodedHash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
