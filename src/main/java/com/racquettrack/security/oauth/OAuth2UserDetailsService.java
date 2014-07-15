package com.racquettrack.security.oauth;

import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * An abstract implementation of an OAuth
 * {@link org.springframework.security.core.userdetails.AuthenticationUserDetailsService}. The class provides
 * standard handling for retrieving the user information from the OAuth Provider using the {@link org.springframework.security.core.Authentication}
 * token.
 *
 * @author paul.wheeler
 */
public class OAuth2UserDetailsService implements
        AuthenticationUserDetailsService, InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2UserDetailsService.class);

    protected OAuth2ServiceProperties oAuth2ServiceProperties = null;
    protected OAuth2UserDetailsLoader oAuth2UserDetailsLoader = null;
    protected OAuth2UserInfoProvider oAuth2UserInfoProvider;

    /**
     * To obtain the user details from the token, the {@link OAuth2UserInfoProvider} is used.
     * This is expected to return enough details such that it is possible to load the
     * {@link UserDetails} from a value in the response from the OAuth Provider, e.g. User Id, Username, Email.
     *
     * If the {@link DefaultOAuth2UserInfoProvider} does not provide enough information that you must implement
     * your own.
     *
     * If no user details are returned by
     * {@link OAuth2UserInfoProvider#getUserInfoFromProvider(Authentication)} then it is
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
        Map<String, Object> userInfo = oAuth2UserInfoProvider.getUserInfoFromProvider(token);
        if (userInfo == null) {
            throw new UsernameNotFoundException("Failed to retrieve user information from OAuth Provider using token:"
                    + token);
        }

        String userId = getUserId(userInfo);

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
    protected String getUserId(Map<String, Object> userInfo) {
        return (String)userInfo.get(oAuth2ServiceProperties.getUserIdName());
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
        Assert.notNull(oAuth2UserDetailsLoader, "An oAuth2UserDetailsLoader must be set");
        Assert.notNull(oAuth2UserInfoProvider, "An oAuth2UserInfoProvider must be set");
    }

    public void setoAuth2ServiceProperties(OAuth2ServiceProperties oAuth2ServiceProperties) {
        this.oAuth2ServiceProperties = oAuth2ServiceProperties;
    }

    public void setoAuth2UserDetailsLoader(OAuth2UserDetailsLoader oAuth2UserDetailsLoader) {
        this.oAuth2UserDetailsLoader = oAuth2UserDetailsLoader;
    }

    public void setoAuth2UserInfoProvider(OAuth2UserInfoProvider oAuth2UserInfoProvider) {
        this.oAuth2UserInfoProvider = oAuth2UserInfoProvider;
    }
}
