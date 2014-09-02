package com.racquettrack.security.oauth;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * An extension point for the OAuth2 authentication mechanism that allows an application to perform
 * arbitrary actions after the user has been created.
 * @author pwheeler
 * @see {@link OAuth2UserDetailsService}
 */
public interface OAuth2PostCreateUserService {

    /**
     * Extension point to allow some actions to be taken after a user has been created.
     * @param userDetails The {@link UserDetails} object created by
     * {@link OAuth2UserDetailsLoader#createUser(java.util.UUID, java.util.Map)}
     * @param userInfo A map representing the user information returned from the OAuth Provider.
     */
    void postCreateUser(UserDetails userDetails, Map<String, Object> userInfo);
}
