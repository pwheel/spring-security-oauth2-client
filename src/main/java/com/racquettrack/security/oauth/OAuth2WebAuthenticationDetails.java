package com.racquettrack.security.oauth;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * A holder of selected HTTP details related to a OAuth2 web authentication request.
 *
 * Extends the default {@link org.springframework.security.web.authentication.WebAuthenticationDetails}.
 *
 * @author paulwheeler
 */
public class OAuth2WebAuthenticationDetails extends WebAuthenticationDetails {

    private String scheme;
    private String host;
    private int port;
    private String contextPath;

    public OAuth2WebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.scheme = request.getScheme();
        this.host = request.getServerName();
        this.port = request.getServerPort();
        this.contextPath = request.getContextPath();
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getContextPath() {
        return contextPath;
    }

    @Override
    public boolean equals(Object o) {
        return EqualsBuilder.reflectionEquals(this, o);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }
}
