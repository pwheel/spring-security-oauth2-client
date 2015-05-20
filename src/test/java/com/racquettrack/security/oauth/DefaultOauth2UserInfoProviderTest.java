package com.racquettrack.security.oauth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;

import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;

/**
 * Tests for {@link DefaultOAuth2UserInfoProvider}.
 *
 * @author paul.wheeler
 */
public class DefaultOauth2UserInfoProviderTest extends AbstractOAuth2Test {
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
    private static final String MOCK_BAD_USER_INFO_RESPONSE = "bob bob bob bob";
    @Mock
    private Authentication token;
    @Mock
    private OAuth2ServiceProperties oAuth2ServiceProperties;
    @InjectMocks
    private DefaultOAuth2UserInfoProvider defaultOAuth2UserInfoProvider;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        initMocks(MOCK_USER_INFO_URI, MOCK_USER_INFO_RESPONSE);

        defaultOAuth2UserInfoProvider.setClient(client);
        given(oAuth2ServiceProperties.getUserInfoUri()).willReturn(MOCK_USER_INFO_URI);
        given(oAuth2ServiceProperties.getAccessTokenName()).willReturn("access_token");
    }

    @Test
    public void shouldGetUserInfoFromProvider() {
        // given

        // when
        Map<String, Object> userInfo = defaultOAuth2UserInfoProvider.getUserInfoFromProvider(token);

        // then
        assertThat(userInfo, notNullValue());
        assertThat((String)userInfo.get("display"), is("paul.wheeler@racquettrack.com"));
    }

    @Test
    public void shouldReturnNullWhenProviderReturnsAnError() {
        // given
        given(clientResponse.getEntity(String.class)).willReturn(MOCK_USER_INFO_ERROR_RESPONSE);
        given(clientResponse.getClientResponseStatus()).willReturn(ClientResponse.Status.BAD_REQUEST);

        // when
        Map<String, Object> userInfo = defaultOAuth2UserInfoProvider.getUserInfoFromProvider(token);

        // then
        assertThat(userInfo, nullValue());
    }

    @Test
    public void shouldReturnNullWhenJacksonMappingFails() {
        // given
        given(clientResponse.getEntity(String.class)).willReturn(MOCK_BAD_USER_INFO_RESPONSE);

        // when
        Map<String, Object> userInfo = defaultOAuth2UserInfoProvider.getUserInfoFromProvider(token);

        // then
        assertThat(userInfo, nullValue());
    }

    @Test
    public void shouldReturnNullWhenJerseyThrowsARuntimeError() {
        // given
        given(builder.get(ClientResponse.class)).willThrow(ClientHandlerException.class);

        // when
        Map<String, Object> userInfo = defaultOAuth2UserInfoProvider.getUserInfoFromProvider(token);

        // then
        assertThat(userInfo, nullValue());
    }

    @Test
    public void shouldIncludeOptionalInfoParams() {
        Map<String,String> additionalInfoParams = Collections.singletonMap("extra_param", "param_value");
        given(oAuth2ServiceProperties.getAdditionalInfoParams()).willReturn(additionalInfoParams);

        Map<String, Object> userInfo = defaultOAuth2UserInfoProvider.getUserInfoFromProvider(token);
        assertThat(userInfo, notNullValue());
        verify(webResource).queryParam("extra_param", "param_value");
    }
}
