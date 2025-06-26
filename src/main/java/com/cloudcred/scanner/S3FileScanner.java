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
        "(?i)AWS_ACCESS_KEY_ID\\s*=\\s*AKIA[0-9A-Z]{16}"
    );

    private static final Pattern MEDIUM_PATTERN = Pattern.compile(
        "(?i)AWS_SECRET_ACCESS_KEY\\s*=\\s*[A-Za-z0-9/+=]{40}"
    );

    private static final Pattern LOW_PATTERN = Pattern.compile(
        "\\bAKIA[0-9A-Z]{16}\\b|\\b[A-Za-z0-9/+=]{40}\\b"
    );

    private final ScanConfig config;

    public S3FileScanner(ScanConfig config) {
        this.config = config;
    }

    // New method: scans all buckets listed in config.s3Buckets
    public List<Finding> scanS3() {
        List<Finding> allFindings = new ArrayList<>();
        if (config.s3Buckets == null || config.s3Buckets.isEmpty()) {
            return allFindings;
        }

        for (String bucket : config.s3Buckets) {
            allFindings.addAll(scanSingleBucket(bucket));
        }

        return allFindings;
    }

    // Existing method: scan a single bucket
    public List<Finding> scanSingleBucket(String bucketName) {
        List<Finding> findings = new ArrayList<>();

        try (S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {

            ListObjectsV2Request listRequest = ListObjectsV2Request.builder()
                    .bucket(bucketName)
                    .prefix(config.s3Prefix)
                    .build();

            ListObjectsV2Response listResponse = s3.listObjectsV2(listRequest);
            for (S3Object s3Object : listResponse.contents()) {
                String key = s3Object.key();
                if (!shouldScan(key)) continue;

                GetObjectRequest getRequest = GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(key)
                        .build();

                try (ResponseInputStream<GetObjectResponse> s3ObjectStream = s3.getObject(getRequest);
                     BufferedReader reader = new BufferedReader(new InputStreamReader(s3ObjectStream))) {

                    String line;
                    int lineNum = 0;
                    while ((line = reader.readLine()) != null) {
                        lineNum++;
                        if (HIGH_PATTERN.matcher(line).find()) {
                            findings.add(new Finding("s3://" + bucketName + "/" + key, lineNum, line.trim(), Severity.HIGH));
                        } else if (MEDIUM_PATTERN.matcher(line).find()) {
                            findings.add(new Finding("s3://" + bucketName + "/" + key, lineNum, line.trim(), Severity.MEDIUM));
                        } else if (LOW_PATTERN.matcher(line).find()) {
                            findings.add(new Finding("s3://" + bucketName + "/" + key, lineNum, line.trim(), Severity.LOW));
                        }
                    }

                } catch (Exception e) {
                    System.out.println("Failed to read S3 object: " + key + " - " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.out.println("Failed to scan S3 bucket: " + bucketName + " - " + e.getMessage());
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
