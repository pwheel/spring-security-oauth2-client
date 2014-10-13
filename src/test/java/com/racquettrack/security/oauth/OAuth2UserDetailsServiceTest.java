package com.racquettrack.security.oauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyMapOf;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import java.io.IOException;
import java.util.Calendar;
import java.util.Map;


import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
/**
 * Tests for the {@link OAuth2UserDetailsService}.
 *
 * @author paul.wheeler
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2UserDetailsServiceTest {
    private static final String MOCK_USER_INFO_RESPONSE = "{\"identities\":{}," +
            "\"display\":\"paul.wheeler@racquettrack.com\"," +
            "\"emails\":{},\"id\":\"f11cb2a8-f179-4f79-b58a-e378fc2ec1d4\"," +
            "\"picture\":\"https://www.dailycred.com/user/pic?user_id=f11cb2a8-f179-4f79-b58a-e378fc2ec1d4&size=50\"," +
            "\"updated_at\":1357670015489,\"created\":1357316236623,\"email\":\"paul.wheeler@racquettrack.com\"," +
            "\"last_logged_in\":1357670015489,\"verified\":false,\"guest\":false,\"attributes\":{}," +
            "\"access_tokens\":{\"dailycred\":\"2c53d030-0f34-471c-92a4-75ee0673f76c\"}," +
            "\"access_token\":\"2c53d030-0f34-471c-92a4-75ee0673f76c\"}";
    private final String MOCK_ACCESS_TOKEN = "2c53d030-0f34-471c-92a4-75ee0673f76c";
    private final String MOCK_USER_UUID = "f11cb2a8-f179-4f79-b58a-e378fc2ec1d4";

    private OAuth2ServiceProperties oAuth2ServiceProperties = new OAuth2ServiceProperties();
    private OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(MOCK_ACCESS_TOKEN);
    private String userId = MOCK_USER_UUID;
    private Map<String, Object> userInfoResponse;

    // Mocks
    @Mock
    private OAuth2UserDetailsLoader oAuth2UserDetailsLoader;
    @Mock
    private OAuth2UserInfoProvider oAuth2UserInfoProvider;
    @Mock
    private OAuth2PostCreateUserService oAuth2PostCreateUserService;
    @InjectMocks
    private OAuth2UserDetailsService oAuth2UserDetailsService;

    private UserDetails user = mock(UserDetails.class);

    @Before
    public void setup() throws IOException {

        oAuth2UserDetailsService.setoAuth2ServiceProperties(oAuth2ServiceProperties);
        userInfoResponse = getUserInfoResponse();

        given(oAuth2UserInfoProvider.getUserInfoFromProvider(oAuth2AuthenticationToken)).willReturn(userInfoResponse);
        given(oAuth2UserDetailsLoader.createUser(userId, userInfoResponse)).willReturn(user);
    }

    /**
     * This will fail as the user doesn't exist and the created timestamp is too old
     */
    @Test(expected = UsernameNotFoundException.class)
    public void shouldFailWithUsernameNotFoundWhenUserDetailsIsNotCreatable() {
        oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);
    }

    @Test
    public void shouldLoadUserDetailsWhenNewUser() throws IOException {
        // given
        given(oAuth2UserDetailsLoader.isCreatable(anyMapOf(String.class, Object.class))).willReturn(true);

        // when
        UserDetails ud = oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);

        // then
        assertThat(ud, is(user));
        verify(oAuth2UserDetailsLoader).createUser(userId, userInfoResponse);
    }

    @Test
    public void shouldLoadUserDetailsWhenExistingUser() {
        // given
        given(oAuth2UserDetailsLoader.getUserByUserId(userId)).willReturn(user);
        given(oAuth2UserDetailsLoader.updateUser(eq(user), anyMapOf(String.class, Object.class))).willReturn(user);

        // when
        UserDetails ud = oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);

        // then
        verify(oAuth2UserDetailsLoader, never()).createUser(any(String.class), anyMapOf(String.class, Object.class));
        verify(oAuth2UserDetailsLoader).updateUser(ud, userInfoResponse);
        assertThat(ud, is(user));
    }

    @Test (expected = UsernameNotFoundException.class)
    public void shouldThrowUsernameNotFoundWhenOAuthUserInfoProviderFails() {
        // given
        given(oAuth2UserInfoProvider.getUserInfoFromProvider(oAuth2AuthenticationToken)).willReturn(null);

        // when
        oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);
    }

    @Test
    public void shouldCallOAuthPostCreateUserServiceWhenNewUser() {
        // given
        given(oAuth2UserDetailsLoader.isCreatable(anyMapOf(String.class, Object.class))).willReturn(true);

        // when
        UserDetails ud = oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);

        // then
        assertThat(ud, notNullValue());
        assertThat(ud, is(user));
        verify(oAuth2PostCreateUserService).postCreateUser(ud, userInfoResponse);
    }

    private Map<String, Object> getUserInfoResponse() throws IOException {
        Map<String, Object> userInfoResponse;
        ObjectMapper mapper = new ObjectMapper();
        TypeReference typeReference = new TypeReference<Map<String,Object>>(){};
        userInfoResponse = mapper.readValue(MOCK_USER_INFO_RESPONSE, typeReference);
        userInfoResponse = updateCreatedTimeOn(userInfoResponse);
        return userInfoResponse;
    }

    /**
     * Update the "created" time in the response object so that new user created can be tested.
     */
    private Map<String, Object> updateCreatedTimeOn(Map<String, Object> userInfoResponse) {
        // Update the created date time
        userInfoResponse.put("created", Calendar.getInstance().getTimeInMillis());
        return userInfoResponse;
    }
}
