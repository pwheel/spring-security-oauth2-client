package com.racquettrack.security.oauth;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.core.util.MultivaluedMapImpl;

/**
 * Processes an OAuth2 authentication request. The request will typically originate from a
 * {@link OAuth2AuthenticationFilter} and will operate on a {@link OAuth2AuthenticationToken}.
 *
 * The OAuth2 processes falls somewhere in between Spring Security's Authenticated and PreAuthenticated models. The
 * Authenticated model is used as we still need to exchange the OAuth code in order to get a OAuth token.
 *
 * For that reason the implementation bears similarities to
 * {@link org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider} in
 * addition to {@link org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider},
 * particularly the implementation of the {@link #authenticate(org.springframework.security.core.Authentication)}
 * method.
 *
 * Once the token is obtained, the
 * AuthenticationUserDetailsService implementation may still throw a UsernameNotFoundException, for example.
 *
 * @author paul.wheeler
 */
public class OAuth2AuthenticationProvider implements AuthenticationProvider, InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthenticationProvider.class);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private AuthenticationUserDetailsService<OAuth2AuthenticationToken> authenticatedUserDetailsService = null;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    boolean throwExceptionWhenTokenRejected = false;
    private OAuth2ServiceProperties oAuth2ServiceProperties = null;
    private Client client = null;

    /**
     * Check whether all required properties have been set.
     */
    public void afterPropertiesSet() {
        Assert.notNull(authenticatedUserDetailsService, "An AuthenticationUserDetailsService must be set");
        Assert.notNull(oAuth2ServiceProperties, "An oAuth2ServiceProperties must be set");
    }

    /**
     * Performs authentication with the same contract as {@link
     * org.springframework.security.authentication.AuthenticationManager#authenticate(org.springframework.security.core.Authentication)}.
     *
     * @param authentication the authentication request object.
     * @return a fully authenticated object including credentials. May return <code>null</code> if the
     *         <code>AuthenticationProvider</code> is unable to support authentication of the passed
     *         <code>Authentication</code> object. In such a case, the next <code>AuthenticationProvider</code> that
     *         supports the presented <code>Authentication</code> class will be tried.
     * @throws org.springframework.security.core.AuthenticationException
     *          if authentication fails.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        LOGGER.debug("OAuth2Authentication authentication request: " + authentication);

        if (authentication.getCredentials() == null) {
            LOGGER.debug("No credentials found in request.");

            if (throwExceptionWhenTokenRejected) {
                throw new BadCredentialsException("No pre-authenticated credentials found in request.");
            }
            return null;
        }

        String token = getAccessToken(authentication);

        OAuth2AuthenticationToken tmpToken = new OAuth2AuthenticationToken(token);

        UserDetails ud = authenticatedUserDetailsService.loadUserDetails(tmpToken);

        userDetailsChecker.check(ud);

        OAuth2AuthenticationToken result =
                new OAuth2AuthenticationToken(ud, token, ud.getAuthorities());
        result.setDetails(authentication.getDetails());

        return result;
    }

    /**
     * Indicate that this provider only supports {@link OAuth2AuthenticationToken} (sub)classes.
     *
     * @param authentication The authentication object presented.
     * @return <code>true</code> if the implementation can more closely evaluate the <code>Authentication</code> class
     *         presented
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Set the AuthenticatedUserDetailsService to be used to load the {@code UserDetails} for the authenticated user.
     *
     * @param uds The {@link AuthenticationUserDetailsService} to use.
     */
    public void setAuthenticatedUserDetailsService(AuthenticationUserDetailsService<OAuth2AuthenticationToken> uds) {
        this.authenticatedUserDetailsService = uds;
    }

    /**
     * If true, causes the provider to throw a BadCredentialsException if the presented authentication
     * request is invalid (contains a null principal or credentials). Otherwise it will just return
     * null. Defaults to false.
     */
    public void setThrowExceptionWhenTokenRejected(boolean throwExceptionWhenTokenRejected) {
        this.throwExceptionWhenTokenRejected = throwExceptionWhenTokenRejected;
    }

    /**
     * Sets the strategy which will be used to validate the loaded <tt>UserDetails</tt> object
     * for the user. Defaults to an {@link org.springframework.security.authentication.AccountStatusUserDetailsChecker}.
     * @param userDetailsChecker The {@link UserDetailsChecker} to use.
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
        Assert.notNull(userDetailsChecker, "userDetailsChacker cannot be null");
        this.userDetailsChecker = userDetailsChecker;
    }

    /**
     * Exchange the current {@link Authentication}, which should be an instance of {@link OAuth2AuthenticationToken}
     * containing an OAuth2 code as the credential, for an OAuth2 token.
     * @param authentication Expected to be an instance of a {@link OAuth2AuthenticationToken}.
     * @return The OAuth2 token from the OAuth Provider.
     */
    protected String getAccessToken(Authentication authentication) {
        String accessToken = null;

        try {
            ClientResponse clientResponse = getClientResponseForAccessTokenRequestFrom(authentication);

            if (!isOkay(clientResponse)) {
                throw new AuthenticationServiceException("Got HTTP error code from OAuth2 provider: "
                        + clientResponse.getStatus());
            }

            String output = getStringRepresentationFrom(clientResponse);
            LOGGER.debug("Output is {}", output);

            Map<String,Object> userData = getUserDataMapFrom(output);
            // Check to see if there was an error or not
            if (userData.containsKey("error")) {
                LOGGER.error("Got error response from the OAuth Provider: {}", output);
                throw new AuthenticationServiceException("Credentials were rejected by the OAuth Provider: " + output);
            }

            accessToken = (String)userData.get(oAuth2ServiceProperties.getAccessTokenName());

        } catch (UniformInterfaceException | ClientHandlerException e) {
            LOGGER.error("Error thrown by Jersey client when exchanging code for token", e);
            throw new AuthenticationServiceException("Error thrown by Jersey client when exchanging code for token", e);
        }

        return accessToken;
    }

    private ClientResponse getClientResponseForAccessTokenRequestFrom(Authentication authentication) {
        Client client = getClient();

        MultivaluedMap<String, String> values = new MultivaluedMapImpl();
        values.add(oAuth2ServiceProperties.getGrantTypeParamName(), oAuth2ServiceProperties.getGrantType());
        values.add(oAuth2ServiceProperties.getClientIdParamName(), oAuth2ServiceProperties.getClientId());
        values.add(oAuth2ServiceProperties.getClientSecretParamName(), oAuth2ServiceProperties.getClientSecret());
        values.add(oAuth2ServiceProperties.getCodeParamName(), (String)  authentication.getCredentials());
        URI redirectUri = redirectUriUsing(authentication);
        values.add(oAuth2ServiceProperties.getRedirectUriParamName(), redirectUri.toString());

        WebResource webResource = client.resource(oAuth2ServiceProperties.getAccessTokenUri());
        ClientResponse clientResponse = webResource
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .type(MediaType.APPLICATION_FORM_URLENCODED)
                .post(ClientResponse.class, values);

        return clientResponse;
    }

    private boolean isOkay(ClientResponse clientResponse) {
        return clientResponse != null && clientResponse.getClientResponseStatus() == ClientResponse.Status.OK;
    }

    private String getStringRepresentationFrom(ClientResponse clientResponse) {
        return clientResponse.getEntity(String.class);
    }

    private Map<String, Object> getUserDataMapFrom(String string) throws AuthenticationServiceException {
        Map<String, Object> userInfo;

        try {
            TypeReference typeReference = new TypeReference<Map<String,Object>>(){};
            userInfo = OBJECT_MAPPER.readValue(string, typeReference);
        } catch (IOException e) {
            LOGGER.error("Error getting user data from Provider", e);
            throw new AuthenticationServiceException("Error getting user data from Provider", e);
        }

        return userInfo;
    }

    /**
     * If a dynamic scheme, host, port, and context path was set then use it to generate the redirect URI.
     * Uses the details on the {@link OAuth2WebAuthenticationDetails} combined with
     * {@link OAuth2ServiceProperties#getRedirectUri()}.
     * @param authentication    The {@link Authentication} token.
     * @return  The dynamic redirect URI, or {@code null} if one could not be obtained.
     */
    private URI redirectUriUsing(Authentication authentication) {
        URI redirectUri;

        Object details = authentication.getDetails();
        if (details != null && OAuth2WebAuthenticationDetails.class.isAssignableFrom(details.getClass())
                && !oAuth2ServiceProperties.getRedirectUri().isAbsolute()) {
            OAuth2WebAuthenticationDetails oAuth2WebAuthenticationDetails = (OAuth2WebAuthenticationDetails) details;
            redirectUri = UriBuilder.fromPath(oAuth2WebAuthenticationDetails.getContextPath())
                    .path(oAuth2ServiceProperties.getRedirectUri().toString())
                    .scheme(oAuth2WebAuthenticationDetails.getScheme())
                    .host(oAuth2WebAuthenticationDetails.getHost())
                    .port(oAuth2WebAuthenticationDetails.getPort())
                    .build();
        } else {
            redirectUri = oAuth2ServiceProperties.getRedirectUri();
        }

        return redirectUri;
    }

    public void setoAuth2ServiceProperties(OAuth2ServiceProperties oAuth2ServiceProperties) {
        this.oAuth2ServiceProperties = oAuth2ServiceProperties;
    }

    /**
     * For caching the {@link Client} object.
     * @return The Jersey {@link Client} object to use.
     */
    public Client getClient() {
        if (client == null) {
            client = Client.create();
        }
        return client;
    }

    /**
     * Intended to be used for unit testing only.
     * @param client The {@link Client} to use. For unit tests allows the client to be mocked.
     */
    public void setClient(Client client) {
        this.client = client;
    }
}
