package com.github.lvan.springouth.authentication;

import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

public class CustomeOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        JwtClaimsSet.Builder claim = context.getClaims();
        Object object = context.getPrincipal().getPrincipal();
        claim.claim("username", object);
    }
}
