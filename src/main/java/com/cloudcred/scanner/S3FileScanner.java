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


// This class is responsible for scanning AWS S3 buckets for credential leaks.
// It uses regex patterns to classify findings by severity, similar to FileScanner.
public class S3FileScanner {

    // Regex for high risk credentials (AWS keys)
    private static final Pattern HIGH_PATTERN = Pattern.compile(
        "(?i)AWS_ACCESS_KEY_ID\\s*=\\s*AKIA[0-9A-Z]{16}"
    );

    // Regex for medium risk credentials (AWS secret keys)
    private static final Pattern MEDIUM_PATTERN = Pattern.compile(
        "(?i)AWS_SECRET_ACCESS_KEY\\s*=\\s*[A-Za-z0-9/+=]{40}"
    );

    // Regex for low risk: long random strings and AWS keys
    private static final Pattern LOW_PATTERN = Pattern.compile(
        "\\bAKIA[0-9A-Z]{16}\\b|\\b[A-Za-z0-9/+=]{40}\\b"
    );

    private final ScanConfig config;

    /**
     * Constructor for S3FileScanner.
     * @param config ScanConfig object with scan settings.
     */
    public S3FileScanner(ScanConfig config) {
        this.config = config;
    }

    /**
     * Scans all buckets listed in config.s3Buckets for leaks.
     * @return List of all findings from all buckets.
     */
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

    /**
     * Scans a single S3 bucket for leaks.
     * @param bucketName Name of the S3 bucket.
     * @return List of findings from the bucket.
     */
    public List<Finding> scanSingleBucket(String bucketName) {
        List<Finding> findings = new ArrayList<>();

        try (S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {

            // List objects in the bucket
            ListObjectsV2Request listRequest = ListObjectsV2Request.builder()
                    .bucket(bucketName)
                    .prefix(config.s3Prefix)
                    .build();

            ListObjectsV2Response listResponse = s3.listObjectsV2(listRequest);
            for (S3Object s3Object : listResponse.contents()) {
                String key = s3Object.key();
                if (!shouldScan(key)) continue;

                // Download and scan each object
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
                        // Check for high, medium, and low severity patterns
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

    /**
     * Determines if an S3 object should be scanned based on its extension.
     * @param key S3 object key (filename).
     * @return true if object should be scanned.
     */
    private boolean shouldScan(String key) {
        String lowerKey = key.toLowerCase();
        for (String ext : config.allowedExtensions) {
            if (lowerKey.endsWith("." + ext)) return true;
        }
        return false;
    }
}
