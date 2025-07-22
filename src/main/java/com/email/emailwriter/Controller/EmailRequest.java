package com.email.emailwriter.Controller;

public class EmailRequest {
    private String emailContent;
    private String tone;

    // --- Getters ---
    public String getEmailContent() {
        return emailContent;
    }

    public String getTone() {
        return tone;
    }

    // --- Setters ---
    public void setEmailContent(String emailContent) {
        this.emailContent = emailContent;
    }

    public void setTone(String tone) {
        this.tone = tone;
    }
}

