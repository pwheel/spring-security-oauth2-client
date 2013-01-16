package com.racquettrack.security.oauth;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

/**
 * Tests for the {@link OAuth2AuthenticationFilterTest} class.
 *
 * @author paul.wheeler
 */
public class OAuth2AuthenticationFilterTest {

    private static final String MOCK_STATE_VALUE ="123456789a";
    private static final String MOCK_CODE_VALUE = "987654321a";
    private static final String MOCK_TOKEN_VALUE ="FOO-TOKEN";
    private OAuth2AuthenticationFilter filter = new OAuth2AuthenticationFilter("/some/url");
    private static final String mockUri = "/some/url";
    private static final String mockQueryString = "state=" + MOCK_STATE_VALUE + "&code=" + MOCK_CODE_VALUE;

    private OAuth2ServiceProperties oAuth2ServiceProperties = new OAuth2ServiceProperties();

    private HttpSession httpSession = Mockito.mock(HttpSession.class);
    private HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
    private AuthenticationManager authenticationManager = Mockito.mock(AuthenticationManager.class);
    private AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private Map<String, String[]> parameters = new HashMap<>();
    private OAuth2AuthenticationToken expectedAuthRequest = new OAuth2AuthenticationToken(MOCK_CODE_VALUE);

    @Before
    public void setup() {
        filter.setoAuth2ServiceProperties(oAuth2ServiceProperties);
        filter.setAuthenticationManager(authenticationManager);

        parameters.put("state", new String[] {MOCK_STATE_VALUE});
        parameters.put("code", new String[] {MOCK_CODE_VALUE});

        Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);
        Mockito.when(httpServletRequest.getParameterMap()).thenReturn(parameters);
        Mockito.when(httpServletRequest.getRequestURI()).thenReturn(mockUri);
        Mockito.when(httpServletRequest.getQueryString()).thenReturn(mockQueryString);

        Mockito.when(httpSession.getAttribute("state")).thenReturn(MOCK_STATE_VALUE);

        expectedAuthRequest.setDetails(authenticationDetailsSource.buildDetails(httpServletRequest));
    }

    @Test
    public void testAuthentication() throws AuthenticationException, IOException, ServletException {

        OAuth2AuthenticationToken fakeResult = new OAuth2AuthenticationToken(mock(UserDetails.class), MOCK_TOKEN_VALUE, null);
        Mockito.when(authenticationManager.authenticate(expectedAuthRequest)).thenReturn(fakeResult);

        Authentication authentication = filter.attemptAuthentication(httpServletRequest, null);

        assertEquals(fakeResult, authentication);
        Mockito.verify(authenticationManager).authenticate(expectedAuthRequest);
    }

    @Test (expected = AuthenticationServiceException.class)
    public void testWrongState() throws AuthenticationException, IOException, ServletException {
        //when(httpSession.getAttribute("state")).thenReturn("FOO-HACKED-STATE");
        parameters.put("state", new String[] {"FOO-HACKED-STATE"});

        filter.attemptAuthentication(httpServletRequest, null);
    }

    @Test (expected = AuthenticationServiceException.class)
    public void testErrorResponse() throws AuthenticationException, IOException, ServletException {
        parameters.clear();
        parameters.put("error", new String[] {"access_denied"});
        parameters.put("error_description", new String[] {"The+user+cancelled+sign-in"});

        filter.attemptAuthentication(httpServletRequest, null);
    }
}
