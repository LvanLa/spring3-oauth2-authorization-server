package com.github.lvan.springouth.authentication.mobile;

import com.github.lvan.springouth.constants.AuthConstants;
import jakarta.annotation.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class OAuth2MobileGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {


    private final String phone;

    private final String code;

    private final Set<String> scopes;

    protected OAuth2MobileGrantAuthenticationToken(String phone, String code, @Nullable Set<String> scopes,
                                                   Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(AuthConstants.AUTHORIZATION_SMS_CODE, clientPrincipal, additionalParameters);
        Assert.hasText(phone, "phone cannot by empty");
        Assert.hasText(code, "code cannot by empty");
        this.phone = phone;
        this.code = code;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }

    public String getPhone() {
        return phone;
    }

    public String getCode() {
        return code;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
