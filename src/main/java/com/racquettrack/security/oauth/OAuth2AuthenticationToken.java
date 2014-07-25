package com.racquettrack.security.oauth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Implementation of an {@link AbstractAuthenticationToken}. This will typically be created by a
 * {@link OAuth2AuthenticationFilter} when processing a callback from the OAuth2 provider, or by a
 * {@link OAuth2AuthenticationProvider} once the principal has been established.
 *
 * There are typically two usages:
 * 1 - Before 'authentication', when instantiated by a {@link OAuth2AuthenticationFilter}. The user has typically been
 * authenticated by the OAuth2 provider, but the principal is not yet known. The principal will typically
 * be null at this point, and the credential will be the OAuth code.
 * 2 - After 'authentication', when instantiated by a {@link OAuth2AuthenticationProvider}. The OAuth code will have
 * been exchanged for an OAuth token (which is now the credential) and the
 * {@link org.springframework.security.core.userdetails.UserDetails} is typically now the principal.
 *
 * @author paul.wheeler
 */
public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {

    private Object credential = null;
    private Object principal = null;
    private String redirectUri = null;

    /**
     * Instantiates an {@link OAuth2AuthenticationToken} with just a {@link #credential}. This constructor
     * would typically be used by a {@link OAuth2AuthenticationFilter}, as the {@link #principal} is not yet known. The
     * {@link AbstractAuthenticationToken} is considered not authenticated.
     * @param credential
     */
    public OAuth2AuthenticationToken(Object credential) {
        super(null);
        this.credential = credential;
        setAuthenticated(false);
    }

    public OAuth2AuthenticationToken(Object principal, Object credential,
                                     Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.credential = credential;
        this.principal = principal;

        setAuthenticated(true);
    }

    /**
     * The credentials that prove the principal is correct. This will be either an OAuth2 code from the OAuth2
     * provider, or will be an OAuth2 token once the code has been exchanged for a token from the OAuth2 provider.
     * Whilst not particularly clean, that seems to fit Spring Security best.
     *
     * @return the credentials that prove the identity of the <code>Principal</code>
     */
    @Override
    public Object getCredentials() {
        return credential;
    }

    /**
     * The identity of the principal being authenticated. In the case of an authentication request with username and
     * password, this would be the username. Callers are expected to populate the principal for an authentication
     * request.
     * <p/>
     * The <tt>AuthenticationManager</tt> implementation will often return an <tt>Authentication</tt> containing
     * richer information as the principal for use by the application. Many of the authentication providers will
     * create a {@code UserDetails} object as the principal.
     *
     * @return the <code>Principal</code> being authenticated or the authenticated principal after authentication.
     */
    @Override
    public Object getPrincipal() {
        return principal;
    }

    /**
     * Gets the redirect URI where this authentication token response should be sent
     * @return redirectUri as an absolute URI in string form or null
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Sets the redirect URI where this authentication token response should be sent
     * @param redirectUri an absolute URI in string form or null
     */
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }


}
