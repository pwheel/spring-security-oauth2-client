package com.racquettrack.security.oauth;

import org.springframework.security.core.Authentication;

import java.util.Map;

/**
 * Responsible for loading a {@link Map} of user information from the OAuth provider. This information
 * is typically necessary in order to create or update a {@link org.springframework.security.core.userdetails.UserDetails}
 * instance.
 *
 * @author paul.wheeler
 */
public interface OAuth2UserInfoProvider {

    /**
     * Retrieves user information from the OAuth Provider. From the returned data
     * it is expected that there is enough information to obtain or create a
     * {@link org.springframework.security.core.userdetails.UserDetails} object from the local database.
     *
     * @param token The {@link OAuth2AuthenticationToken} token.
     * @return A {@link Map} representation of the JSON data retrieved from the OAuth Provider.
     */
    Map<String,Object> getUserInfoFromProvider(Authentication token);
}
