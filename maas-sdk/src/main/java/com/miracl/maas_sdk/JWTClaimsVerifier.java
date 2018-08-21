package com.miracl.maas_sdk;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import net.minidev.json.JSONObject;

import java.util.Date;

public class JWTClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {
    private void verifyClaims(JWTClaimsSet claimsSet) throws BadJWTException {
        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime == null) {
            throw new BadJWTException("Missing token expiration claim");
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
