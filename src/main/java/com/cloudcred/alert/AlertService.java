
package com.cloudcred.alert;

import com.cloudcred.model.Finding;

// This service is responsible for sending alerts when a leak is detected.
// For now, it just prints to the console, but you could extend it to send emails or notifications.
public class AlertService {
    /**
     * Print an alert to the console for a detected finding.
     * @param finding The detected leak or secret.
     */
    public void sendAlert(Finding finding) {
        System.out.println("⚠️ ALERT: " + finding);
    }
}
