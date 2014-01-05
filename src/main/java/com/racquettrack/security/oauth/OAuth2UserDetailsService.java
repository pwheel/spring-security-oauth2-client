package com.racquettrack.security.oauth;

import com.sun.jersey.api.client.*;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

/**
 * An abstract implementation of an OAuth
 * {@link org.springframework.security.core.userdetails.AuthenticationUserDetailsService}. The class provides
 * standard handling for retrieving the user information from the OAuth Provider using the {@link org.springframework.security.core.Authentication}
 * token.
 *
 * @author paul.wheeler
 */
public class OAuth2UserDetailsService<OAuth2AuthenticationToken> implements
        AuthenticationUserDetailsService, InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2UserDetailsService.class);

    protected OAuth2ServiceProperties oAuth2ServiceProperties = null;
    protected OAuth2UserDetailsLoader oAuth2UserDetailsLoader = null;

    private Client client =  null;

    /**
     * Subclasses should call the {@link #getUserInfoFromProvider(org.springframework.security.core.Authentication)}
     * method to obtain the user details from the token. They are then expected to be able to load the
     * {@link UserDetails} from a value in the response from the OAuth Provider, e.g. User Id, Username, Email.
     *
     * If no user details are returned by
     * {@link #getUserInfoFromProvider(org.springframework.security.core.Authentication)} then it is
     * recommended that subclasses throw a {@link UsernameNotFoundException}.
     *
     * @param token The pre-authenticated authentication token
     * @return UserDetails for the given authentication token, never null.
     * @throws org.springframework.security.core.userdetails.UsernameNotFoundException
     *          if no user details can be found for the given authentication
     *          token
     */
    @Override
    public UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException {
        LOGGER.debug("loadUserDetails called with: " + token);
        Map<String, Object> userInfo = getUserInfoFromProvider(token);
        if (userInfo == null) {
            throw new UsernameNotFoundException("Failed to retrieve user information from OAuth Provider using token:"
                    + token);
        }

        UUID userId = getUserId(userInfo);

        UserDetails userDetails = oAuth2UserDetailsLoader.getUserByUserId(userId);

        // If we didn't find the user account, check to see if an account can be created
        if (userDetails == null && oAuth2UserDetailsLoader.isCreatable(userInfo)) {
            LOGGER.debug("Okay to create new user {}", userId);
            userDetails = oAuth2UserDetailsLoader.createUser(userId, userInfo);
            LOGGER.info("Created new user: {}", userDetails);
            userDetails = postCreateUser(userDetails, userInfo);
        } else if (userDetails != null) {
            userDetails = oAuth2UserDetailsLoader.updateUser(userDetails, userInfo);
        }
        if (userDetails == null) {
            throw new UsernameNotFoundException("Failed to find userId: " + userId + ", from token: " + token);
        }
        return userDetails;
    }

    /**
     * Extension point to allow sub classes to optionally do some processing after a user has been created. For example
     * they could make a call to update the OAuth Provider or retrieve additional information from the OAuth Provider.
     * @param userDetails The {@link UserDetails} object created by
     * {@link OAuth2UserDetailsLoader#createUser(java.util.UUID, java.util.Map)}
     * @param userInfo A map representing the user information returned from the OAuth Provider.
     * @return The {@link UserDetails} object, which may have been updated.
     */
    public UserDetails postCreateUser(UserDetails userDetails, Map<String, Object> userInfo) {
        return userDetails;
    }

    /**
     * Gets the user id from the JSON object returned by the OAuth Provider. Uses the
     * {@link OAuth2ServiceProperties#getUserIdName()} to obtain the property from the
     * map.
     * @param userInfo The JSON string converted into a {@link Map}.
     * @return The user id, a {@link UUID}.
     */
    protected UUID getUserId(Map<String, Object> userInfo) {
        String uuid = (String)userInfo.get(oAuth2ServiceProperties.getUserIdName());
        return UUID.fromString(uuid);
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
        Assert.notNull(oAuth2ServiceProperties, "An oAuth2ServiceProperties must be set");
        Assert.notNull(oAuth2UserDetailsLoader, "A oAuth2UserDetailsLoader must be set");
    }

    /**
     * Retrieves user information from the OAuth Provider. This method is expected to be called by subclasses in their
     * {@link #loadUserDetails(org.springframework.security.core.Authentication)} methods. From the returned data
     * it is expected that they have enough information to obtain a {@link UserDetails} object from the local database.
     *
     * @param token The {@link Authentication} token, typically a {@link OAuth2AuthenticationToken}.
     * @return A {@link Map} representation of the JSON data retrieved from the OAuth Provider.
     */
    protected Map<String,Object> getUserInfoFromProvider(Authentication token) {
        Map<String,Object> userInfo = null;

        try {
            Client client = getClient();

            WebResource webResource = client
                    .resource(oAuth2ServiceProperties.getUserInfoUri())
                    .queryParam(oAuth2ServiceProperties.getAccessTokenName(), (String)token.getCredentials());

            ClientResponse clientResponse = webResource.accept("application/json")
                    .get(ClientResponse.class);

            String output = clientResponse.getEntity(String.class);
            LOGGER.debug("Output is {}", output);

            if (clientResponse.getStatus() == 200) {
                ObjectMapper mapper = new ObjectMapper();
                userInfo = mapper.readValue(output, Map.class);
                //username = (String)userData.get("username");
            } else {
                LOGGER.error("Got error response (code={}) from Provider: {}", clientResponse.getStatus(), output);
            }

        } catch (UniformInterfaceException | ClientHandlerException | IOException e) {
            LOGGER.error("Error getting user info from Provider", e);
        }

        return userInfo;
    }

    public void setoAuth2ServiceProperties(OAuth2ServiceProperties oAuth2ServiceProperties) {
        this.oAuth2ServiceProperties = oAuth2ServiceProperties;
    }

    public void setoAuth2UserDetailsLoader(OAuth2UserDetailsLoader oAuth2UserDetailsLoader) {
        this.oAuth2UserDetailsLoader = oAuth2UserDetailsLoader;
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
