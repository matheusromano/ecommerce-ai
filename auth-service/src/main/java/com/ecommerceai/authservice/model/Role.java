package com.ecommerceai.authservice.model;

public enum Role {
    ROLE_USER("User", "Regular user with basic permissions"),
    ROLE_ADMIN("Admin", "Administrator with full permissions"),
    ROLE_DESIGNER("Designer", "Designer with design management permissions"),
    ROLE_MODERATOR("Moderator", "Moderator with content moderation permissions");

    private final String displayName;
    private final String description;

    Role(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
