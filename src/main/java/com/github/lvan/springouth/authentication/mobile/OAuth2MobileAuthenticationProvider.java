package com.github.lvan.springouth.authentication.mobile;

import com.github.lvan.springouth.constants.AuthConstants;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.util.*;


public class OAuth2MobileAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private final Log logger = LogFactory.getLog(this.getClass());
    private final OAuth2AuthorizationService authorizationService;
    private final UserDetailsService userDetailsService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public OAuth2MobileAuthenticationProvider(HttpSecurity http) {
        Assert.notNull(http, "authorizationService cannot be null");
        this.authorizationService = getAuthorizationService(http);
        this.tokenGenerator = getTokenGenerator(http);
        this.userDetailsService = getOptionalBean(http,UserDetailsService.class);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2MobileGrantAuthenticationToken resourceAuthentication = (OAuth2MobileGrantAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resourceAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthConstants.AUTHORIZATION_SMS_CODE)) {
            throw new OAuth2AuthenticationException("unauthorized_client");
        } else {
            Set<String> authorizedScopes = Collections.emptySet();
            if (!CollectionUtils.isEmpty(resourceAuthentication.getScopes())) {
                Iterator var6 = resourceAuthentication.getScopes().iterator();
                while (var6.hasNext()) {
                    String requestedScope = (String) var6.next();
                    if (!registeredClient.getScopes().contains(requestedScope)) {
                        throw new OAuth2AuthenticationException("invalid_scope");
                    }
                }
                authorizedScopes = new LinkedHashSet(resourceAuthentication.getScopes());
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Validated token request parameters");
            }
            //验证手机和验证码
           UserDetails details =  userDetailsService.loadUserByUsername(resourceAuthentication.getPhone());
            if(null == details){
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }
            // 验证码
//            if()
//            {
//                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
//            }

            Authentication principal = new MobileAuthenticationToken(resourceAuthentication.getPhone(), resourceAuthentication.getCode(),null);
            DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(principal)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(authorizedScopes)
                    .authorizationGrantType(AuthConstants.AUTHORIZATION_SMS_CODE)
                    .authorizationGrant(resourceAuthentication);

            OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
            OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
            if (generatedAccessToken == null) {
                OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the access token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
                throw new OAuth2AuthenticationException(error);
            } else {
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Generated access token");
                }


                OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(), generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
                OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                        .principalName(principal.getName())
                        .attribute(Principal.class.getName(),principal)
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD).
                                authorizedScopes(authorizedScopes);
                if (generatedAccessToken instanceof ClaimAccessor) {
                    authorizationBuilder.token(accessToken, (metadata) -> {
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims());
                    });
                } else {
                    authorizationBuilder.accessToken(accessToken);
                }

                OAuth2Authorization authorization = authorizationBuilder.build();
                this.authorizationService.save(authorization);
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Saved authorization");
                    this.logger.trace("Authenticated token request");
                }

                return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
            }
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2MobileGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        } else {
            throw new OAuth2AuthenticationException("invalid_client");
        }
    }

    static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
        OAuth2AuthorizationService authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);
        if (authorizationService == null) {
            authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }

            httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }

        return authorizationService;
    }

    static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(httpSecurity.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            int var10003 = beansMap.size();
            String var10004 = type.getName();
            throw new NoUniqueBeanDefinitionException(type, var10003, "Expected single matching bean of type '" + var10004 + "' but found " + beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        } else {
            return !beansMap.isEmpty() ? beansMap.values().iterator().next() : null;
        }
    }

    static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = (OAuth2TokenGenerator) httpSecurity.getSharedObject(OAuth2TokenGenerator.class);
        if (tokenGenerator == null) {
            tokenGenerator = (OAuth2TokenGenerator) getOptionalBean(httpSecurity, OAuth2TokenGenerator.class);
            if (tokenGenerator == null) {
                JwtGenerator jwtGenerator = getJwtGenerator(httpSecurity);
                OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
                OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer = getAccessTokenCustomizer(httpSecurity);
                if (accessTokenCustomizer != null) {
                    accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
                }

                OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
                if (jwtGenerator != null) {
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(new OAuth2TokenGenerator[]{jwtGenerator, accessTokenGenerator, refreshTokenGenerator});
                } else {
                    tokenGenerator = new DelegatingOAuth2TokenGenerator(new OAuth2TokenGenerator[]{accessTokenGenerator, refreshTokenGenerator});
                }
            }

            httpSecurity.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        }

        return  tokenGenerator;
    }

    private static JwtGenerator getJwtGenerator(HttpSecurity httpSecurity) {
        JwtGenerator jwtGenerator = (JwtGenerator) httpSecurity.getSharedObject(JwtGenerator.class);
        if (jwtGenerator == null) {
            JwtEncoder jwtEncoder = getJwtEncoder(httpSecurity);
            if (jwtEncoder != null) {
                jwtGenerator = new JwtGenerator(jwtEncoder);
                OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = getJwtCustomizer(httpSecurity);
                if (jwtCustomizer != null) {
                    jwtGenerator.setJwtCustomizer(jwtCustomizer);
                }

                httpSecurity.setSharedObject(JwtGenerator.class, jwtGenerator);
            }
        }

        return jwtGenerator;
    }

    private static JwtEncoder getJwtEncoder(HttpSecurity httpSecurity) {
        JwtEncoder jwtEncoder = httpSecurity.getSharedObject(JwtEncoder.class);
        if (jwtEncoder == null) {
            jwtEncoder = getOptionalBean(httpSecurity, JwtEncoder.class);
            if (jwtEncoder == null) {
                JWKSource<SecurityContext> jwkSource = getJwkSource(httpSecurity);
                if (jwkSource != null) {
                    jwtEncoder = new NimbusJwtEncoder(jwkSource);
                }
            }

            if (jwtEncoder != null) {
                httpSecurity.setSharedObject(JwtEncoder.class, jwtEncoder);
            }
        }

        return (JwtEncoder) jwtEncoder;
    }

    static JWKSource<SecurityContext> getJwkSource(HttpSecurity httpSecurity) {
        JWKSource<SecurityContext> jwkSource = (JWKSource)httpSecurity.getSharedObject(JWKSource.class);
        if (jwkSource == null) {
            jwkSource = getOptionalBean(httpSecurity, JWKSource.class);
            if (jwkSource != null) {
                httpSecurity.setSharedObject(JWKSource.class, jwkSource);
            }
        }
        return jwkSource;
    }

    private static OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer(HttpSecurity httpSecurity) {
        return (OAuth2TokenCustomizer) getOptionalBean(httpSecurity, OAuth2TokenCustomizer.class);
    }

    private static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> getAccessTokenCustomizer(HttpSecurity httpSecurity) {
        return (OAuth2TokenCustomizer) getOptionalBean(httpSecurity, OAuth2TokenCustomizer.class);
    }
}
