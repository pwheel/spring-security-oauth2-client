package com.racquettrack.security.oauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;

import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;

/**
 * Tests for {@link OAuth2AuthenticationProvider}.
 *
 * @author paul.wheeler
 */
public class OAuth2AuthenticationProviderTest extends AbstractOAuth2Test {

    private final String MOCK_OAUTH_CODE = RandomStringUtils.randomAlphanumeric(10);
    private final String MOCK_ACCESS_URI = "https://mock.com/oauth/access";
    private final String MOCK_ACCESS_TOKEN = "2c53d030-0f34-471c-92a4-75ee0673f76c";
    private final String MOCK_ACCESS_RESPONSE = "{\"worked\":true,\"access_token\":\"" + MOCK_ACCESS_TOKEN + "\"}";
    private final String MOCK_ACCESS_RESPONSE_FAILURE = "{\"error\": {\"message\": \"The authorization code is invalid.\"," +
            "\"code\": 400,\"type\": \"invalid_grant\"},\"worked\": false}";
    private OAuth2AuthenticationProvider oAuth2AuthenticationProvider = new OAuth2AuthenticationProvider();
    private OAuth2ServiceProperties oAuth2ServiceProperties = new OAuth2ServiceProperties();
    private OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(MOCK_OAUTH_CODE);
    private OAuth2AuthenticationToken expectedTmpToken = new OAuth2AuthenticationToken(MOCK_ACCESS_TOKEN);
    private UserDetails userDetails = mock(UserDetails.class);

    // Mocks
    private AuthenticationUserDetailsService<OAuth2AuthenticationToken> authenticatedUserDetailsService =
            mock(AuthenticationUserDetailsService.class);

    @Before
    public void setup() {
        initMocks(MOCK_ACCESS_URI, MOCK_ACCESS_RESPONSE);

        oAuth2AuthenticationProvider.setoAuth2ServiceProperties(oAuth2ServiceProperties);
        oAuth2AuthenticationProvider.setAuthenticatedUserDetailsService(authenticatedUserDetailsService);
        oAuth2AuthenticationProvider.setClient(client);

        oAuth2ServiceProperties.setAccessTokenUri(MOCK_ACCESS_URI);

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
        assertThat((OAuth2AuthenticationToken)authentication, is(expectedResult));
    }

    @Test(expected = AuthenticationException.class)
    public void shouldThrowAuthenticationExceptionWhenAuthorizationCodeIsInvalid() {
        // given
        given(clientResponse.getEntity(String.class)).willReturn(MOCK_ACCESS_RESPONSE_FAILURE);

        // when
        oAuth2AuthenticationProvider.authenticate(oAuth2AuthenticationToken);
    }

    @Test(expected = AuthenticationException.class)
    public void shouldThrowAuthenticationExceptionWhenJerseyThrowsARuntimeError() {
        // given
        given(builder.post(eq(ClientResponse.class), anyObject())).willThrow(ClientHandlerException.class);

        // when
        oAuth2AuthenticationProvider.authenticate(oAuth2AuthenticationToken);
    }

    @Test(expected = AuthenticationException.class)
    public void shouldThrowAuthenticationExceptionWhenMappingFails() {
        // given
        given(clientResponse.getEntity(String.class)).willReturn("bob bob bob");

        // when
        oAuth2AuthenticationProvider.authenticate(oAuth2AuthenticationToken);
    }
}
