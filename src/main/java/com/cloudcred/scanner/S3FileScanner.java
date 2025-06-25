package com.cloudcred.scanner;

import com.cloudcred.model.Finding;
import com.cloudcred.model.Finding.Severity;
import com.cloudcred.model.ScanConfig;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.regex.Pattern;

public class S3FileScanner {

    private static final Pattern HIGH_PATTERN = Pattern.compile(
            "(AKIA[0-9A-Z]{16})|(aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40})"
    );
    private static final Pattern MEDIUM_PATTERN = Pattern.compile(
            "(?i)(secret|token|key).{0,20}[=:]?\s*[A-Za-z0-9/+=]{30,60}"
    );
    private static final Pattern LOW_PATTERN = Pattern.compile(
            "\b[A-Za-z0-9/+=]{40}\b"
    );

    private final ScanConfig config;

    public S3FileScanner(ScanConfig config) {
        this.config = config;
    }

    public List<Finding> scanS3() {
        List<Finding> findings = new ArrayList<>();
        if (config.s3Bucket == null || config.s3Bucket.isEmpty()) {
            return findings;
        }

        try (S3Client s3 = S3Client.builder()
                .region(Region.AWS_GLOBAL)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {

            ListObjectsV2Request listRequest = ListObjectsV2Request.builder()
                    .bucket(config.s3Bucket)
                    .prefix(config.s3Prefix)
                    .build();

            ListObjectsV2Response listResponse = s3.listObjectsV2(listRequest);
            for (S3Object s3Object : listResponse.contents()) {
                String key = s3Object.key();
                if (!shouldScan(key)) continue;

                GetObjectRequest getRequest = GetObjectRequest.builder()
                        .bucket(config.s3Bucket)
                        .key(key)
                        .build();

                try (ResponseInputStream<GetObjectResponse> s3ObjectStream = s3.getObject(getRequest);
                     BufferedReader reader = new BufferedReader(new InputStreamReader(s3ObjectStream))) {

                    String line;
                    int lineNum = 0;
                    while ((line = reader.readLine()) != null) {
                        lineNum++;

                        if (HIGH_PATTERN.matcher(line).find()) {
                            findings.add(new Finding("s3://" + key, lineNum, line.trim(), Severity.HIGH));
                        } else if (MEDIUM_PATTERN.matcher(line).find()) {
                            findings.add(new Finding("s3://" + key, lineNum, line.trim(), Severity.MEDIUM));
                        } else if (LOW_PATTERN.matcher(line).find()) {
                            findings.add(new Finding("s3://" + key, lineNum, line.trim(), Severity.LOW));
                        }
                    }

                } catch (Exception e) {
                    System.out.println("Failed to read S3 object: " + key + " - " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.out.println("Failed to scan S3 bucket: " + e.getMessage());
        }

        return findings;
    }

    private boolean shouldScan(String key) {
        String lowerKey = key.toLowerCase();
        for (String ext : config.allowedExtensions) {
            if (lowerKey.endsWith("." + ext)) return true;
        }
        return false;
    }
}
