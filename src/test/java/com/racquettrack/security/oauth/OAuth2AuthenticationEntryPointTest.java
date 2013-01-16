package com.racquettrack.security.oauth;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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
    private HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
    private HttpServletResponse httpServletResponse = Mockito.mock(HttpServletResponse.class);
    private HttpSession httpSession = Mockito.mock(HttpSession.class);
    private OAuth2AuthenticationEntryPoint oAuth2AuthenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    @Before
    public void setup() {
        oAuth2ServiceProperties.setUserAuthorisationUri(MOCK_USER_AUTHORISATION_URI);
        oAuth2ServiceProperties.setClientId(MOCK_CLIENT_ID);
        oAuth2ServiceProperties.setRedirectUri(MOCK_REDIRECT_URI);

        Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);

        oAuth2AuthenticationEntryPoint.setoAuth2ServiceProperties(oAuth2ServiceProperties);
    }

    @Test
    public void testEntryPoint() throws IOException, ServletException {

        oAuth2AuthenticationEntryPoint.commence(httpServletRequest, httpServletResponse, null);

        Mockito.verify(httpServletResponse).sendRedirect(Matchers.startsWith(generateExpectedURIStart()));
    }

    @Test
    public void testEntryPointWithAdditionalParams() throws IOException, ServletException {
        Map<String, String> params = new HashMap<>();
        params.put("fake_key_1", "FOO-ONE");
        params.put("fake_key_2", "FOO-TWO");
        oAuth2ServiceProperties.setAdditionalAuthParams(params);
        String authUriEndsWith = "&fake_key_1=FOO-ONE&fake_key_2=FOO-TWO";

        oAuth2AuthenticationEntryPoint.commence(httpServletRequest, httpServletResponse, null);

        Mockito.verify(httpServletResponse).sendRedirect(Matchers.startsWith(generateExpectedURIStart()));
        Mockito.verify(httpServletResponse).sendRedirect(Matchers.endsWith(authUriEndsWith));
    }

    public String generateExpectedURIStart() {
        StringBuilder authorisationUri = new StringBuilder();
        authorisationUri.append(MOCK_USER_AUTHORISATION_URI)
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
