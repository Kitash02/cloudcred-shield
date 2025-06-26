package com.cloudcred.fixer;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Fixer {

    public void handleFindings(List<Finding> findings) {
        if (findings.isEmpty()) return;

        Map<String, List<Finding>> groupedByFile = new HashMap<>();
        for (Finding finding : findings) {
            groupedByFile.computeIfAbsent(finding.getFilePath(), k -> new ArrayList<>()).add(finding);
        }

        for (Map.Entry<String, List<Finding>> entry : groupedByFile.entrySet()) {
            String filePath = entry.getKey();
            List<Finding> fileFindings = entry.getValue();

            if (filePath.startsWith("s3://")) {
                handleS3File(filePath, fileFindings);
            } else {
                handleLocalFile(filePath, fileFindings);
            }
        }
    }

    private void handleLocalFile(String filePath, List<Finding> fileFindings) {
        try {
            List<String> originalLines = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    originalLines.add(line);
                }
            }

            String[] modifiedLines = new String[originalLines.size()];
            System.arraycopy(originalLines.toArray(new String[0]), 0, modifiedLines, 0, originalLines.size());

            Scanner scanner = new Scanner(System.in);

            for (Finding finding : fileFindings) {
                int idx = finding.getLineNumber() - 1;
                System.out.println("\nFile: " + filePath);
                System.out.println("Line " + finding.getLineNumber() + ": " + originalLines.get(idx));
                System.out.println("Severity: " + finding.getSeverity());
                System.out.println("Choose how to handle this finding:");
                System.out.println("  1. Leave as is");
                System.out.println("  2. Replace with REDACTED hash (SHA256)");
                System.out.println("  3. Replace with placeholder (e.g., REMOVED_CREDENTIAL)");
                System.out.print("Your choice (default 2): ");

                String choice = scanner.nextLine().trim();
                switch (choice) {
                    case "1":
                        break;
                    case "3":
                        modifiedLines[idx] = "REMOVED_CREDENTIAL";
                        break;
                    case "2":
                    default:
                        modifiedLines[idx] = "[REDACTED_SHA256:" + sha256(originalLines.get(idx)) + "]";
                        break;
                }
            }

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
                for (String line : modifiedLines) {
                    writer.write(line);
                    writer.newLine();
                }
            }

            System.out.println("✅ File updated: " + filePath);

        } catch (IOException e) {
            System.out.println("❌ Error processing file: " + filePath + " - " + e.getMessage());
        }
    }

    private void handleS3File(String s3Path, List<Finding> fileFindings) {
        String bucket = s3Path.split("/")[2];
        String key = s3Path.substring("s3://".length() + bucket.length() + 1);

        try (S3Client s3 = S3Client.create()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    s3.getObject(r -> r.bucket(bucket).key(key)), StandardCharsets.UTF_8));

            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) lines.add(line);

            String[] modifiedLines = new String[lines.size()];
            System.arraycopy(lines.toArray(new String[0]), 0, modifiedLines, 0, lines.size());

            Scanner scanner = new Scanner(System.in);
            for (Finding finding : fileFindings) {
                int idx = finding.getLineNumber() - 1;
                System.out.println("\nFile: s3://" + bucket + "/" + key);
                System.out.println("Line " + finding.getLineNumber() + ": " + lines.get(idx));
                System.out.println("Severity: " + finding.getSeverity());
                System.out.println("Choose how to handle this finding:");
                System.out.println("  1. Leave as is");
                System.out.println("  2. Replace with REDACTED hash (SHA256)");
                System.out.println("  3. Replace with placeholder (e.g., REMOVED_CREDENTIAL)");
                System.out.print("Your choice (default 2): ");

                String choice = scanner.nextLine().trim();
                switch (choice) {
                    case "1":
                        break;
                    case "3":
                        modifiedLines[idx] = "REMOVED_CREDENTIAL";
                        break;
                    case "2":
                    default:
                        modifiedLines[idx] = "[REDACTED_SHA256:" + sha256(lines.get(idx)) + "]";
                        break;
                }
            }

            File tempFile = File.createTempFile("s3fix", null);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
                for (String l : modifiedLines) {
                    writer.write(l);
                    writer.newLine();
                }
            }

            s3.putObject(PutObjectRequest.builder().bucket(bucket).key(key).build(), tempFile.toPath());
            tempFile.delete();
            System.out.println("✅ S3 file updated: s3://" + bucket + "/" + key);

        } catch (IOException e) {
            System.out.println("❌ Error fixing S3 file: " + s3Path + " - " + e.getMessage());
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
