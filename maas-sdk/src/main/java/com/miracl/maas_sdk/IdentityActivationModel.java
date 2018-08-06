package com.miracl.maas_sdk;

public class IdentityActivationModel {
    public static final String EXPIRATION_TIME = "expireTime";
    static final String USER_ID_KEY = "userId";
    static final String MPIN_ID_HASH_KEY = "hashMPinId";
    static final String ACTIVATION_KEY = "activateKey";
    private final String subject;
    private String mPinIdHash;
    private String activationKey;

    IdentityActivationModel(String mPinIdHash, String activateKey, String subject)
    {
        this.subject = subject;
        this.mPinIdHash = mPinIdHash;
        this.activationKey = activateKey;
    }

    String getМPinIdHash() {
        return mPinIdHash;
    }

    String getActivationKey() {
        return activationKey;
    }

    public String getSubject() {
        return subject;
    }
}
