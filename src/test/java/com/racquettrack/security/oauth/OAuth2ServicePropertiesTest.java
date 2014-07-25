package com.racquettrack.security.oauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;

public class OAuth2ServicePropertiesTest extends AbstractOAuth2Test {

    final String ABSOLUTE_URI = "http://fake.example.org/absolute/uri";
    final String SOURCE_URI = "http://my.custom.domain/context/resource.request?foo=bar";
    final String SOURCE_CONTEXT = "/context";
    final String RELATIVE_URI = "/relative/uri.example";
    final String RELATIVE_URI_NOSLASH = "relative/uri.example";

    OAuth2ServiceProperties properties;
    HttpServletRequest mockRequest = mock(HttpServletRequest.class);

    @Before
    public void setup() throws IOException {
        properties = new OAuth2ServiceProperties();

    }

    @Test
    public void shouldNotChangeAbsoluteRedirectUri() throws IOException {
        properties.setRedirectUri(ABSOLUTE_URI);

        assertThat(properties.getAbsoluteRedirectUri(mockRequest), equalTo(ABSOLUTE_URI));
    }

    @Test
    public void shouldChangeRelativeRedirectUri() throws IOException {
        properties.setRedirectUri(RELATIVE_URI);

        given(mockRequest.getRequestURL()).willReturn(new StringBuffer(SOURCE_URI));
        given(mockRequest.getContextPath()).willReturn(SOURCE_CONTEXT);

        assertThat(properties.getAbsoluteRedirectUri(mockRequest), equalTo("http://my.custom.domain/context/relative/uri.example"));
    }

    @Test
    public void shouldChangeRelativeNoSlashRedirectUri() throws IOException {
        properties.setRedirectUri(RELATIVE_URI_NOSLASH);

        given(mockRequest.getRequestURL()).willReturn(new StringBuffer(SOURCE_URI));
        given(mockRequest.getContextPath()).willReturn(SOURCE_CONTEXT);

        assertThat(properties.getAbsoluteRedirectUri(mockRequest), equalTo("http://my.custom.domain/context/relative/uri.example"));
    }
}
