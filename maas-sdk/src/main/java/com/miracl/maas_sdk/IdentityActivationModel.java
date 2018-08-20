package com.miracl.maas_sdk;

public class IdentityActivationModel {
    public static final String EXPIRATION_TIME = "expireTime";
    static final String USER_ID_KEY = "userId";
    static final String USER_ID_KEY_PUSH = "userID";
    static final String MPIN_ID_HASH_KEY = "hashMPinId";
    static final String MPIN_ID_HASH_KEY_PUSH = "hashMPinID";
    static final String ACTIVATION_KEY = "activateKey";
    private final String subject;
    private String mpinIdHash;
    private String activationKey;

    IdentityActivationModel(String mpinIdHash, String activateKey, String subject)
    {
        this.subject = subject;
        this.mpinIdHash = mpinIdHash;
        this.activationKey = activateKey;
    }

    String getМPinIdHash() {
        return mpinIdHash;
    }

    String getActivationKey() {
        return activationKey;
    }

    public String getSubject() {
        return subject;
    }
}
