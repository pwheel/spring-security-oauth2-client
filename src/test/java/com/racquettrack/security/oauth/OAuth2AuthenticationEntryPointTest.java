package com.racquettrack.security.oauth;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.endsWith;
import static org.mockito.Matchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Test for {@link OAuth2AuthenticationEntryPoint}.
 *
 * @author paul.wheeler
 */
public class OAuth2AuthenticationEntryPointTest {

    private static final String MOCK_USER_AUTHORISATION_URI = "https://mock.com/oauth/auth";
    private static final String MOCK_REDIRECT_URI = "http://localhost:8080/oauth/callback";
    private static final String MOCK_CLIENT_ID = UUID.randomUUID().toString();
    private OAuth2ServiceProperties oAuth2ServiceProperties = new OAuth2ServiceProperties();
    private HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
    private HttpServletResponse httpServletResponse = mock(HttpServletResponse.class);
    private HttpSession httpSession = mock(HttpSession.class);
    private OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    @Before
    public void setup() {
        oAuth2ServiceProperties.setUserAuthorisationUri(MOCK_USER_AUTHORISATION_URI);
        oAuth2ServiceProperties.setClientId(MOCK_CLIENT_ID);
        oAuth2ServiceProperties.setRedirectUri(MOCK_REDIRECT_URI);

        given(httpServletRequest.getSession()).willReturn(httpSession);

        oAuth2AuthenticationEntryPoint.setOAuth2ServiceProperties(oAuth2ServiceProperties);
    }

    @Test
    public void shouldSendRedirectWhenEntryPointIsHit() throws IOException, ServletException {
        // given

        // when
        oAuth2AuthenticationEntryPoint.commence(httpServletRequest, httpServletResponse, null);

        // then
        verify(httpServletResponse).sendRedirect(startsWith(generateExpectedURIStart()));
    }

    @Test
    public void shouldRedirectWithAdditionalParams() throws IOException, ServletException {
        // given
        Map<String, String> params = new HashMap<>();
        params.put("fake_key_1", "FOO-ONE");
        params.put("fake_key_2", "FOO-TWO");
        oAuth2ServiceProperties.setAdditionalAuthParams(params);
        String authUriEndsWith = "&fake_key_1=FOO-ONE&fake_key_2=FOO-TWO";

        // when
        oAuth2AuthenticationEntryPoint.commence(httpServletRequest, httpServletResponse, null);

        // then
        verify(httpServletResponse).sendRedirect(startsWith(generateExpectedURIStart()));
        verify(httpServletResponse).sendRedirect(endsWith(authUriEndsWith));
    }

    private String generateExpectedURIStart() {
        StringBuilder authorisationUri = new StringBuilder()
                .append(MOCK_USER_AUTHORISATION_URI)
                .append("?")
                .append("client_id")
                .append("=")
                .append(MOCK_CLIENT_ID)
                .append("&")
                .append("redirect_uri")
                .append("=")
                .append(MOCK_REDIRECT_URI)
                .append("&")
                .append("response_type")
                .append("=")
                .append("code")
                .append("&")
                .append("state")
                .append("=");
                //.append(state); // Can't test this part, it's randomly generated

        return authorisationUri.toString();
    }
}
