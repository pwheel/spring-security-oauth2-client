package com.racquettrack.security.oauth;

import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Provides a {@link AuthenticationEntryPoint} for initiating the OAuth2 authentication process.
 * The Entry Point will redirect the user to a URL constructed from the values declared in the
 * {@link OAuth2ServiceProperties}.
 *
 *
 * @author paul.wheeler
 */
public class OAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthenticationEntryPoint.class);
    private static final int STATE_RANDOM_STRING_LENGTH = 10;

    private OAuth2ServiceProperties oAuth2ServiceProperties = null;

    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        // Generate a state and store it in the session to verify when redirected
        String state = RandomStringUtils.randomAlphanumeric(STATE_RANDOM_STRING_LENGTH);
        request.getSession().setAttribute(oAuth2ServiceProperties.getStateParamName(), state);

        // Build the authorisation uri
        StringBuilder authorisationUri = new StringBuilder();
        authorisationUri.append(oAuth2ServiceProperties.getUserAuthorisationUri())
                .append("?")
                .append(oAuth2ServiceProperties.getClientIdParamName())
                .append("=")
                .append(oAuth2ServiceProperties.getClientId())
                .append("&")
                .append(oAuth2ServiceProperties.getRedirectUriParamName())
                .append("=")
                .append(oAuth2ServiceProperties.getRedirectUri())
                .append("&")
                .append(oAuth2ServiceProperties.getResponseTypeParamName())
                .append("=")
                .append(oAuth2ServiceProperties.getResponseType())
                .append("&")
                .append(oAuth2ServiceProperties.getStateParamName())
                .append("=")
                .append(state);

        // Allow for subclasses to override behaviour
        authorisationUri.append(constructAdditionalAuthParameters(oAuth2ServiceProperties.getAdditionalAuthParams()));

        String url = authorisationUri.toString();

        LOG.debug("authorizationUrl : {}", url);

        response.sendRedirect(url);
    }

    /**
     * Provided so that subclasses can override the default behaviour. Note that the recommended method to add
     * additional parameters is via {@link OAuth2ServiceProperties#setAdditionalAuthParams(java.util.Map)}.

     * Subclasses should never return null, as this was result in "null" being appended to the redirect uri
     * (see {@link StringBuilder#append(StringBuffer)}. Even if there are no additional parameters, return a
     * StringBuilder.
     *
     * @param additionalParameters A Map of additional parameters to set.
     * @return A {@link StringBuilder} containing the additional parameters, if there are any. Do not return null.
     */
    protected StringBuilder constructAdditionalAuthParameters(Map<String, String> additionalParameters) {
        StringBuilder result = new StringBuilder();

        if (additionalParameters != null &&
                additionalParameters.isEmpty() == false) {
            for (Map.Entry<String, String> entry : additionalParameters.entrySet()) {
                result.append("&")
                        .append(entry.getKey())
                        .append("=")
                        .append(entry.getValue());
            }
        }

        return result;
    }

    /**
     * Invoked by a BeanFactory after it has set all bean properties supplied
     * (and satisfied BeanFactoryAware and ApplicationContextAware).
     * <p>This method allows the bean instance to perform initialization only
     * possible when all bean properties have been set and to throw an
     * exception in the event of misconfiguration.
     *
     * @throws Exception in the event of misconfiguration (such
     *                   as failure to set an essential property) or if initialization fails.
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(oAuth2ServiceProperties, "oAuth2ServiceProperties must be set");
    }

    public void setoAuth2ServiceProperties(OAuth2ServiceProperties oAuth2ServiceProperties) {
        this.oAuth2ServiceProperties = oAuth2ServiceProperties;
    }
}
