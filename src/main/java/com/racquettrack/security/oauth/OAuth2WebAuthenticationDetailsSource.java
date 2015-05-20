package com.racquettrack.security.oauth;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * Implementation of {@link AuthenticationDetailsSource} which builds the details object from
 * an <tt>HttpServletRequest</tt> object, creating a {@code OAuth2WebAuthenticationDetails}.
 *
 * Based on the default {@link org.springframework.security.web.authentication.WebAuthenticationDetails}.
 *
 * @author paulwheeler
 */
public class OAuth2WebAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

    /**
     * @param context the {@code HttpServletRequest} object.
     * @return the {@code WebAuthenticationDetails} containing information about the current request
     */
    public OAuth2WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new OAuth2WebAuthenticationDetails(context);
    }
}
