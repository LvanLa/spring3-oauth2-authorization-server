package com.github.lvan.springouth.authentication.mobile;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

import static com.github.lvan.springouth.constants.AuthConstants.AUTHORIZATION_SMS_CODE;


public class OAuth2MobileAuthenticationConverter implements AuthenticationConverter {

    private static final String REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AUTHORIZATION_SMS_CODE.getValue().equals(grantType)) {
            return null;
        } else {
            Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
            MultiValueMap<String, String> parameters = getParameters(request);
            String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
            if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
                throwError("invalid_request", OAuth2ParameterNames.SCOPE, REQUEST_ERROR_URI);
            }
            Set<String> requestedScopes = null;
            if (StringUtils.hasText(scope)) {
                requestedScopes = new HashSet(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
            }
            String phoneParameterName = "phone";
            String phone = parameters.getFirst(phoneParameterName);
            if (!StringUtils.hasText(phone) || parameters.get(phoneParameterName).size() != 1) {
                throwError("invalid_request", phoneParameterName, REQUEST_ERROR_URI);
            }
            String codeParameterName = "code";
            String code = parameters.getFirst(codeParameterName);
            if (!StringUtils.hasText(code) || parameters.get(codeParameterName).size() != 1) {
                throwError("invalid_request", codeParameterName, REQUEST_ERROR_URI);
            }

            Map<String, Object> additionalParameters = new HashMap();
            parameters.forEach((key, value) -> {
                if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
                        && !key.equals(OAuth2ParameterNames.SCOPE)
                        && !key.equals(OAuth2ParameterNames.USERNAME)
                        && !key.equals(OAuth2ParameterNames.PASSWORD)
                ) {
                    additionalParameters.put(key, value.get(0));
                }

            });
            return new OAuth2MobileGrantAuthenticationToken(phone, code, requestedScopes, clientPrincipal, additionalParameters);
        }
    }

    static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                String[] var3 = values;
                int var4 = values.length;

                for (int var5 = 0; var5 < var4; ++var5) {
                    String value = var3[var5];
                    parameters.add(key, value);
                }
            }

        });
        return parameters;
    }

    static void throwError(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throw new OAuth2AuthenticationException(error);
    }
}
