package com.racquettrack.security.oauth;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Contains configuration properties for the OAuth2 Service Provider to authenticate against.
 *
 * The class allows parameter names to be changed if OAuth 2 Providers (e.g. Facebook with access token)
 * have deviated slightly from the spec, or have implemented earlier drafts.
 *
 * @author paul.wheeler
 */
public class OAuth2ServiceProperties implements InitializingBean {
    private static final String DEFAULT_CLIENT_SECRET_PARAM_NAME = "client_secret";
    private static final String DEFAULT_CLIENT_ID_PARAM_NAME    = "client_id";
    private static final String DEFAULT_REDIRECT_URI_PARAM_NAME = "redirect_uri";
    private static final String DEFAULT_CODE_PARAM_NAME         = "code";
    private static final String DEFAULT_ACCESS_TOKEN_NAME       = "access_token";
    private static final String DEFAULT_GRANT_TYPE_PARAM_NAME   = "grant_type";
    private static final String DEFAULT_GRANT_TYPE              = "authorization_code";
    private static final String DEFAULT_RESPONSE_TYPE_PARAM_NAME = "response_type";
    /**
     * Only code is supported.
     */
    private static final String DEFAULT_RESPONSE_TYPE           = "code";
    private static final String DEFAULT_STATE_PARAM_NAME        = "state";
    private static final String DEFAULT_USER_ID_NAME            = "id";

    // Mandatory properties
    private String userAuthorisationUri = null;
    private Map<String, String> additionalAuthParams = null;
    private URI redirectUri = null;
    private String accessTokenUri = null;
    private String clientId = null;
    private String clientSecret = null;
    private String userInfoUri = null;
    private Map<String, String> additionalInfoParams = null;

    // Optional properties
    private String accessTokenName = DEFAULT_ACCESS_TOKEN_NAME;
    private String clientSecretParamName = DEFAULT_CLIENT_SECRET_PARAM_NAME;
    private String clientIdParamName = DEFAULT_CLIENT_ID_PARAM_NAME;
    private String grantTypeParamName = DEFAULT_GRANT_TYPE_PARAM_NAME;
    private String grantType = DEFAULT_GRANT_TYPE;
    private String redirectUriParamName = DEFAULT_REDIRECT_URI_PARAM_NAME;
    private String responseTypeParamName = DEFAULT_RESPONSE_TYPE_PARAM_NAME;
    private String responseType = DEFAULT_RESPONSE_TYPE;
    private String stateParamName = DEFAULT_STATE_PARAM_NAME;
    private String codeParamName = DEFAULT_CODE_PARAM_NAME;
    private String userIdName = DEFAULT_USER_ID_NAME;

    /**
     * Check whether all required properties have been set
     *
     * @throws Exception in the event of misconfiguration (such
     *                   as failure to set an essential property) or if initialization fails.
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userAuthorisationUri, "The userAuthorisationUri must be set");
        Assert.notNull(redirectUri, "The redirectUri must be set");
        Assert.notNull(accessTokenUri, "The accessTokenUri must be set");
        Assert.notNull(clientId, "The clientId must be set");
        Assert.notNull(clientSecret, "The clientSecret must be set");
        Assert.notNull(userInfoUri, "The userInfoUri must be set");
    }

    public String getUserAuthorisationUri() {
        return userAuthorisationUri;
    }

    public void setUserAuthorisationUri(String userAuthorisationUri) {
        this.userAuthorisationUri = userAuthorisationUri;
    }

    public Map<String, String> getAdditionalAuthParams() {
        return additionalAuthParams;
    }

    public void setAdditionalAuthParams(Map<String, String> additionalAuthParams) {
        this.additionalAuthParams = additionalAuthParams;
    }

    /**
     * The redirectUri which will handle responses from the OAuth2 provider.
     * Can be relative or absolute
     * @return The redirect {@link URI}
     */
    public URI getRedirectUri() {
        return redirectUri;
    }

    /**
     * The redirectUri which will handle responses from the OAuth2 provider.
     * Can be relative or absolute
     * @param redirectUri The redirect URI as a string; will be converted to a {@link URI}
     */
    public void setRedirectUri(String redirectUri) throws URISyntaxException {
        this.redirectUri = new URI(redirectUri);
    }

    public String getAccessTokenUri() {
        return accessTokenUri;
    }

    public void setAccessTokenUri(String accessTokenUri) {
        this.accessTokenUri = accessTokenUri;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAccessTokenName() {
        return accessTokenName;
    }

    public void setAccessTokenName(String accessTokenName) {
        this.accessTokenName = accessTokenName;
    }

    public String getClientIdParamName() {
        return clientIdParamName;
    }

    public void setClientIdParamName(String clientIdParamName) {
        this.clientIdParamName = clientIdParamName;
    }

    public String getGrantTypeParamName() {
        return grantTypeParamName;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getRedirectUriParamName() {
        return redirectUriParamName;
    }

    public void setRedirectUriParamName(String redirectUriParamName) {
        this.redirectUriParamName = redirectUriParamName;
    }

    public String getResponseTypeParamName() {
        return responseTypeParamName;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getStateParamName() {
        return stateParamName;
    }

    public String getCodeParamName() {
        return codeParamName;
    }

    public String getClientSecretParamName() {
        return clientSecretParamName;
    }

    public String getUserInfoUri() {
        return userInfoUri;
    }

    public void setUserInfoUri(String userInfoUri) {
        this.userInfoUri = userInfoUri;
    }

    public Map<String, String> getAdditionalInfoParams() {
        return additionalInfoParams;
    }

    public void setAdditionalInfoParams(Map<String, String> additionalInfoParams) {
        this.additionalInfoParams = additionalInfoParams;
    }

    public String getUserIdName() {
        return userIdName;
    }

    public void setUserIdName(String userIdName) {
        this.userIdName = userIdName;
    }
}
