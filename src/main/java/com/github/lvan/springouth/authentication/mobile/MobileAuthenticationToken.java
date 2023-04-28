package com.github.lvan.springouth.authentication.mobile;

import com.github.lvan.springouth.constants.AuthConstants;
import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.*;

public class MobileAuthenticationToken extends AbstractAuthenticationToken {


    private Object principal;

    private String code;

    public MobileAuthenticationToken(Object principal,String code) {
        super(null);
        this.principal = principal;
        this.code = code;
    }

    public MobileAuthenticationToken(Object principal,String code,Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.code = code;
        super.setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return code;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
