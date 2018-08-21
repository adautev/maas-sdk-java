package com.miracl.maas_sdk;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import net.minidev.json.JSONObject;

import java.util.Date;

public class PushJWTClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {
    private void verifyClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime == null) {
            throw new BadJWTException("Missing token expiration claim");
        }

        JSONObject eventsClaim = (JSONObject) claimsSet.getClaim("events");

        if (eventsClaim == null) {
            throw new MiraclSystemException("\"events\" key not found in activation JWT");
        }
        Object newUser = eventsClaim.get("newUser");
        if (newUser == null) {
            throw new MiraclSystemException("\"newUser\" key not found in activation JWT");
        }
        String mpinIdHash = ((JSONObject) newUser).getAsString(IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH);
        if (mpinIdHash == null || mpinIdHash.equals("")) {
            throw new MiraclSystemException(String.format("\"%s\" key not found in activation JWT", IdentityActivationModel.MPIN_ID_HASH_KEY_PUSH));
        }
        String activationKey = ((JSONObject) newUser).getAsString(IdentityActivationModel.ACTIVATION_KEY);
        if (activationKey == null || activationKey.equals("")) {
            throw new MiraclSystemException(String.format("\"%s\" key not found in activation JWT", IdentityActivationModel.ACTIVATION_KEY));
        }
        if (!MiraclConfig.ISSUER.equals(claimsSet.getIssuer())) {
            throw new BadJWTException("Token issuer not accepted");
        }
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);
        verifyClaims(claimsSet);
    }

    @Override
    public void verify(JWTClaimsSet claimsSet) throws BadJWTException {
        super.verify(claimsSet);
        verifyClaims(claimsSet);
    }
}
