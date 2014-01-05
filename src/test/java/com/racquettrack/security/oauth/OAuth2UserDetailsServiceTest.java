package com.racquettrack.security.oauth;

import junit.framework.Assert;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.IOException;
import java.util.Calendar;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.*;

/**
 * Tests for the {@link OAuth2UserDetailsService}.
 *
 * @author paul.wheeler
 */
public class OAuth2UserDetailsServiceTest extends AbstractOAuth2Test {
    private static final String MOCK_USER_INFO_URI = "https://mock.com/oauth/user.me";
    private static final String MOCK_USER_INFO_RESPONSE = "{\"identities\":{}," +
            "\"display\":\"paul.wheeler@racquettrack.com\"," +
            "\"emails\":{},\"id\":\"f11cb2a8-f179-4f79-b58a-e378fc2ec1d4\"," +
            "\"picture\":\"https://www.dailycred.com/user/pic?user_id=f11cb2a8-f179-4f79-b58a-e378fc2ec1d4&size=50\"," +
            "\"updated_at\":1357670015489,\"created\":1357316236623,\"email\":\"paul.wheeler@racquettrack.com\"," +
            "\"last_logged_in\":1357670015489,\"verified\":false,\"guest\":false,\"attributes\":{}," +
            "\"access_tokens\":{\"dailycred\":\"2c53d030-0f34-471c-92a4-75ee0673f76c\"}," +
            "\"access_token\":\"2c53d030-0f34-471c-92a4-75ee0673f76c\"}";
    private static final String MOCK_USER_INFO_ERROR_RESPONSE = "{\"error\": " +
            "{\"message\": \"Invalid OAuth access token.\",\"code\": 190,\"type\": \"OAuthException\"}," +
            "\"worked\": false}";
    private final String MOCK_ACCESS_TOKEN = "2c53d030-0f34-471c-92a4-75ee0673f76c";
    private final String MOCK_USER_UUID = "f11cb2a8-f179-4f79-b58a-e378fc2ec1d4";

    private OAuth2UserDetailsService oAuth2UserDetailsService = new OAuth2UserDetailsService();
    private OAuth2ServiceProperties oAuth2ServiceProperties = new OAuth2ServiceProperties();
    private OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(MOCK_ACCESS_TOKEN);
    private UserDetails user = mock(UserDetails.class);
    private UUID userId = UUID.fromString(MOCK_USER_UUID);
    private Map<String, Object> userInfoResponse;

    // Mocks
    private OAuth2UserDetailsLoader oAuth2UserDetailsLoader = Mockito.mock(OAuth2UserDetailsLoader.class);

    @Before
    public void setup() throws IOException {
        initMocks(MOCK_USER_INFO_URI, MOCK_USER_INFO_RESPONSE);
        oAuth2ServiceProperties.setUserInfoUri(MOCK_USER_INFO_URI);

        oAuth2UserDetailsService.setoAuth2ServiceProperties(oAuth2ServiceProperties);
        oAuth2UserDetailsService.setoAuth2UserDetailsLoader(oAuth2UserDetailsLoader);
        oAuth2UserDetailsService.setClient(client);

        ObjectMapper mapper = new ObjectMapper();
        userInfoResponse = mapper.readValue(MOCK_USER_INFO_RESPONSE, Map.class);

//        user.setEmail("paul.wheeler@racquettrack.com");
//        user.setPassword("password1");

        when(oAuth2UserDetailsLoader.createUser(userId, userInfoResponse)).thenReturn(user);
    }

    /**
     * Update the "created" time in the response object so that new user created can be tested.
     * @throws IOException
     */
    public void updateCreatedTime() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        // Update the created date time
        userInfoResponse.put("created", Calendar.getInstance().getTimeInMillis());
        String response = mapper.writeValueAsString(userInfoResponse);
        when(clientResponse.getEntity(String.class)).thenReturn(response);
        when(oAuth2UserDetailsLoader.createUser(userId, userInfoResponse)).thenReturn(user);
    }

    /**
     * This will fail as the user doesn't exist and the created timestamp is too old
     */
    @Test(expected = UsernameNotFoundException.class)
    public void testLoadUserDetailsNotCreatable() {
        oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);
    }

    @Test
    public void testLoadUserDetailsNewUser() throws IOException {
        updateCreatedTime();
        when(oAuth2UserDetailsLoader.isCreatable(any(Map.class))).thenReturn(true);

        UserDetails ud = oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);
        Assert.assertEquals(user, ud);
        Mockito.verify(oAuth2UserDetailsLoader).createUser(userId, userInfoResponse);
    }

    @Test
    public void testLoadUserDetails() {
        // given
        when(oAuth2UserDetailsLoader.getUserByUserId(userId)).thenReturn(user);
        when(oAuth2UserDetailsLoader.updateUser(eq(user),anyMap())).thenReturn(user);

        // when
        UserDetails ud = oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);

        // then
        Mockito.verify(oAuth2UserDetailsLoader, Mockito.never()).createUser(any(UUID.class), any(Map.class));
        Assert.assertEquals(user, ud);
    }

    @Test (expected = UsernameNotFoundException.class)
    public void testLoadUserDetailsErrorResponseFromProvider() {
        when(clientResponse.getEntity(String.class)).thenReturn(MOCK_USER_INFO_ERROR_RESPONSE);
        when(clientResponse.getStatus()).thenReturn(400);

        oAuth2UserDetailsService.loadUserDetails(oAuth2AuthenticationToken);
    }
}
