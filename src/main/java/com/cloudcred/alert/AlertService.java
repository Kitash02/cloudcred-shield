package com.cloudcred.alert;

import com.cloudcred.model.Finding;

public class AlertService {
    public void sendAlert(Finding finding) {
        System.out.println("⚠️ ALERT: " + finding);
    }
}
