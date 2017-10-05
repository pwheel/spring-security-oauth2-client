package com.racquettrack.security.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2AuthenticationProvider}.
 *
 * @author paul.wheeler
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthenticationProviderTest extends AbstractOAuth2Test {

    private final String PARAM_REDIRECT_URI = "redirect_uri";
    private final String REDIRECT_URI = "https://localhost:443/app/callback";
    private final String MOCK_OAUTH_CODE = RandomStringUtils.randomAlphanumeric(10);
    private final String MOCK_ACCESS_URI = "https://mock.com/oauth/access";
    private final String MOCK_ACCESS_TOKEN = "2c53d030-0f34-471c-92a4-75ee0673f76c";
    private final String MOCK_ACCESS_RESPONSE = "{\"worked\":true,\"access_token\":\"" + MOCK_ACCESS_TOKEN + "\"}";
    private final String MOCK_ACCESS_RESPONSE_FAILURE = "{\"error\": {\"message\": \"The authorization code is invalid.\"," +
            "\"code\": 400,\"type\": \"invalid_grant\"},\"worked\": false}";
    private OAuth2ServiceProperties oAuth2ServiceProperties = new OAuth2ServiceProperties();
    private OAuth2AuthenticationToken oAuth2AuthenticationToken = authToken();
    private OAuth2AuthenticationToken expectedTmpToken = new OAuth2AuthenticationToken(MOCK_ACCESS_TOKEN);
    @Mock
    private UserDetails userDetails;
    @Mock
    private AuthenticationUserDetailsService<OAuth2AuthenticationToken> authenticatedUserDetailsService;
    @InjectMocks
    private OAuth2AuthenticationProvider oAuth2AuthenticationProvider;
    @Captor
    private ArgumentCaptor<Entity<Form>> formEntityCaptor;

    @Before
    public void setup() throws URISyntaxException, IOException {
        initMocks(MOCK_ACCESS_URI, MOCK_ACCESS_RESPONSE);

        oAuth2AuthenticationProvider.setoAuth2ServiceProperties(oAuth2ServiceProperties);
        oAuth2AuthenticationProvider.setAuthenticatedUserDetailsService(authenticatedUserDetailsService);
        oAuth2AuthenticationProvider.setClient(client);

        oAuth2ServiceProperties.setAccessTokenUri(MOCK_ACCESS_URI);
        oAuth2ServiceProperties.setRedirectUriParamName(PARAM_REDIRECT_URI);
        oAuth2ServiceProperties.setRedirectUri(REDIRECT_URI);

        // By default mock everything to okay
        given(userDetails.isAccountNonExpired()).willReturn(true);
        given(userDetails.isAccountNonLocked()).willReturn(true);
        given(userDetails.isCredentialsNonExpired()).willReturn(true);
        given(userDetails.isEnabled()).willReturn(true);
        given(authenticatedUserDetailsService.loadUserDetails(expectedTmpToken)).willReturn(userDetails);
    }

    @Test
    public void shouldAuthenticate() {
        // given
        OAuth2AuthenticationToken expectedResult =
                new OAuth2AuthenticationToken(userDetails, MOCK_ACCESS_TOKEN, userDetails.getAuthorities());

        // when
        Authentication authentication = oAuth2AuthenticationProvider.authenticate(oAuth2AuthenticationToken);

        // then
        assertThat(authentication, notNullValue());
        assertThat(authentication, is(expectedResult));
    }

    @Test(expected = AuthenticationException.class)
    public void shouldThrowAuthenticationExceptionWhenAuthorizationCodeIsInvalid() throws IOException {
        // given
        TypeReference typeReference = new TypeReference<Map<String,Object>>(){};
        Map<String, Object> responseAsMap = getObjectMapper().readValue(MOCK_ACCESS_RESPONSE_FAILURE, typeReference);
        given(response.readEntity(new GenericType<Map<String, Object>>() {})).willReturn(responseAsMap);

        // when
        oAuth2AuthenticationProvider.authenticate(oAuth2AuthenticationToken);
    }

    @Test(expected = AuthenticationException.class)
    public void shouldThrowAuthenticationExceptionWhenJerseyThrowsARuntimeError() {
        // given
        given(builder.post(anyObject())).willThrow(ProcessingException.class);

        // when
        oAuth2AuthenticationProvider.authenticate(oAuth2AuthenticationToken);
    }

    @Test
    public void shouldUseOAuth2WebAuthenticationDetailsWhenAvailableAndRedirectIsNotAbsolute() throws URISyntaxException {
        // given
        OAuth2WebAuthenticationDetails authDetails = oAuth2Details();
        OAuth2AuthenticationToken authTokenWithDetails = authToken();
        authTokenWithDetails.setDetails(authDetails);
        oAuth2ServiceProperties.setRedirectUri("/callback");

        // when
        oAuth2AuthenticationProvider.authenticate(authTokenWithDetails);

        // then
        verify(builder).post(formEntityCaptor.capture());
        MultivaluedMap<String, String> values = formEntityCaptor.getValue().getEntity().asMap();
        assertThat(values.getFirst(PARAM_REDIRECT_URI), is("https://host.com:443/path/callback"));
    }

    @Test
    public void shouldUseStandardRedirectWhenNoOAuth2WebAuthenticationDetailsAreAvailable() {
        // given
        WebAuthenticationDetails webAuthDetails = mock(WebAuthenticationDetails.class);
        OAuth2AuthenticationToken authTokenWithWebDetails = authToken();
        authTokenWithWebDetails.setDetails(webAuthDetails);

        // when
        oAuth2AuthenticationProvider.authenticate(authTokenWithWebDetails);

        // then
        verify(builder).post(formEntityCaptor.capture());
        MultivaluedMap<String, String> values = formEntityCaptor.getValue().getEntity().asMap();
        assertThat(values.getFirst(PARAM_REDIRECT_URI), is(REDIRECT_URI));
    }

    @Test
    public void shouldUseAbsoluteURLEvenWhenOAuth2WebAuthenticationDetailsAreAvailable() {
        // given
        OAuth2WebAuthenticationDetails authDetails = oAuth2Details();
        OAuth2AuthenticationToken authTokenWithDetails = authToken();
        authTokenWithDetails.setDetails(authDetails);

        // when
        oAuth2AuthenticationProvider.authenticate(authTokenWithDetails);

        // then
        verify(builder).post(formEntityCaptor.capture());
        MultivaluedMap<String, String> values = formEntityCaptor.getValue().getEntity().asMap();
        assertThat(values.getFirst(PARAM_REDIRECT_URI), is("https://localhost:443/app/callback"));
    }

    private OAuth2AuthenticationToken authToken() {
        return new OAuth2AuthenticationToken(MOCK_OAUTH_CODE);
    }

    private OAuth2WebAuthenticationDetails oAuth2Details() {
        OAuth2WebAuthenticationDetails authDetails = mock(OAuth2WebAuthenticationDetails.class);
        given(authDetails.getScheme()).willReturn("https");
        given(authDetails.getHost()).willReturn("host.com");
        given(authDetails.getPort()).willReturn(443);
        given(authDetails.getContextPath()).willReturn("/path");
        return authDetails;
    }
}
