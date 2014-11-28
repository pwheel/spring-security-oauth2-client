package com.racquettrack.security.oauth;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

/**
 * An implementation of a {@link AbstractAuthenticationProcessingFilter} that responds to responses from the OAuth
 * Provider. The configuration of the defaultFilterProcessesUrl passed to the constructor must be such that the filter
 * is listening on the URL passed to the OAuth Provider and configured in the property
 * {@link OAuth2ServiceProperties#redirectUri}.
 *
 * @see OAuth2ServiceProperties
 * @author paul.wheeler
 */
public class OAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2AuthenticationFilter.class);

    private OAuth2ServiceProperties oAuth2ServiceProperties = null;

    /**
     * Define the suffix url on which the filter will listen for HTTP requests. Must be configured such that the filter
     * is listening on the URL specifified in the property
     * {@link OAuth2ServiceProperties#redirectUri}.
     *
     * @param defaultFilterProcessesUrl URL to filter in, see
     * {@link OAuth2ServiceProperties#getRedirectUri()}
     */
    public OAuth2AuthenticationFilter(final String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    /**
    * Performs actual authentication.
    * <p/>
    * The implementation should do one of the following:
    * <ol>
    * <li>Return a populated authentication token for the authenticated user, indicating successful authentication</li>
    * <li>Return null, indicating that the authentication process is still in progress. Before returning, the
    * implementation should perform any additional work required to complete the process.</li>
    * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
    * </ol>
    *
    * @param request  from which to extract parameters and perform the authentication
    * @param response the response, which may be needed if the implementation has to do a redirect as part of a
    *                 multi-stage authentication process (such as OpenID).
    * @return the authenticated user token, or null if authentication is incomplete.
    * @throws org.springframework.security.core.AuthenticationException
    *          if authentication fails.
    */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String code = null;

        if (LOG.isDebugEnabled()) {
            String url = request.getRequestURI();
            String queryString = request.getQueryString();
            LOG.debug("attemptAuthentication on url {}?{}", url, queryString);
        }

        // request parameters
        final Map<String, String[]> parameters = request.getParameterMap();
        LOG.debug("Got Parameters: {}", parameters);

        // Check to see if there was an error response from the OAuth Provider
        checkForErrors(parameters);

        // Check state parameter to avoid cross-site-scripting attacks
        checkStateParameter(request.getSession(), parameters);

        final String codeValues[] = parameters.get(oAuth2ServiceProperties.getCodeParamName());
        if (codeValues != null && codeValues.length > 0) {
            code = codeValues[0];
            LOG.debug("Got code {}", code);
        }

        OAuth2AuthenticationToken authRequest = new OAuth2AuthenticationToken(code);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Check the state parameter to ensure it is the same as was originally sent. Subclasses can override this
     * behaviour if they so choose, but it is not recommended.
     * @param session The http session, which will contain the original scope as an attribute.
     * @param parameters The parameters received from the OAuth 2 Provider, which should contain the same state as
     *                   originally sent to it and stored in the http session.
     * @throws AuthenticationException If the state differs from the original.
     */
    protected void checkStateParameter(HttpSession session, Map<String, String[]> parameters)
            throws AuthenticationException {

        String originalState = (String)session.getAttribute(oAuth2ServiceProperties.getStateParamName());
        String receivedStates[] = parameters.get(oAuth2ServiceProperties.getStateParamName());

        // There should only be one entry in the array, if there are more they will be ignored.
        if (receivedStates == null || receivedStates.length == 0 ||
                !receivedStates[0].equals(originalState)) {
            String errorMsg = String.format("Received states %s was not equal to original state %s",
                    receivedStates, originalState);
            LOG.error(errorMsg);
            throw new AuthenticationServiceException(errorMsg);
        }
    }

    /**
     * Checks to see if an error was returned by the OAuth Provider and throws an {@link AuthenticationException} if
     * it was.
     * @param parameters Parameters received from the OAuth Provider.
     * @throws AuthenticationException If an error was returned by the OAuth Provider.
     */
    protected void checkForErrors(Map<String, String[]> parameters) throws AuthenticationException {
        final String errorValues[] = parameters.get("error");
        final String errorReasonValues[] = parameters.get("error_reason");
        final String errorDescriptionValues[] = parameters.get("error_description");

        if (errorValues != null && errorValues.length > 0) {
            final String error = errorValues[0];
            final String errorReason = errorReasonValues != null && errorReasonValues.length > 0 ?
                    errorReasonValues[0] : null;
            final String errorDescription = errorDescriptionValues != null && errorDescriptionValues.length > 0 ?
                    errorDescriptionValues[0] : null;
            final String errorText = String.format("An error was returned by the OAuth Provider: error=%s, " +
                    "error_reason=%s, error_description=%s", error, errorReason, errorDescription);
            LOG.info(errorText);
            throw new AuthenticationServiceException(errorText);
        }
    }

    /**
     * Provided so that subclasses may configure what is put into the authentication request's details
     * property.
     *
     * @param request that an authentication request is being created for
     * @param authRequest the authentication request object that should have its details set
     */
    protected void setDetails(HttpServletRequest request, OAuth2AuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    public void setoAuth2ServiceProperties(OAuth2ServiceProperties oAuth2ServiceProperties) {
        this.oAuth2ServiceProperties = oAuth2ServiceProperties;
    }

    /**
     * Check properties are set
     */
    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet();
        Assert.notNull(oAuth2ServiceProperties);
        Assert.isTrue(oAuth2ServiceProperties.getRedirectUri().toString().endsWith(super.getFilterProcessesUrl()),
                "The filter must be configured to be listening on the redirect_uri in OAuth2ServiceProperties");
    }
}
