package com.racquettrack.security.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * A default implementation of {@link OAuth2UserInfoProvider} that obtains a {@link Map} of properties
 * from the OAuth endpoint as specified in {@link OAuth2ServiceProperties}. The OAuth endpoint is expected to
 * return JSON data.
 *
 * @author paul.wheeler
 */
public class DefaultOAuth2UserInfoProvider implements OAuth2UserInfoProvider, InitializingBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2UserInfoProvider.class);

    private Client client =  null;
    private OAuth2ServiceProperties oAuth2ServiceProperties;

    @Override
    public Map<String, Object> getUserInfoFromProvider(Authentication token) {
        Map<String,Object> userInfo = null;

        try {
            Response response = getResponseFromProviderUsing(token);

            if (isOkay(response)) {
                userInfo = getUserInfoMapFrom(response);
            } else {
                LOGGER.error("Got error response (code={}) from Provider, output={}", response.getStatus(),
                        response.readEntity(String.class));
            }
        } catch (WebApplicationException | ProcessingException e) {
            LOGGER.error("Jersey client threw a runtime exception", e);
        }

        return userInfo;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(oAuth2ServiceProperties, "An oAuth2ServiceProperties must be set");
    }

    /**
     * Calls the external OAuth provider and returns the Jersey {@link Response} object.
     * @param token The {@link Authentication} token to use in the call.
     * @return The {@link Response} object.
     */
    private Response getResponseFromProviderUsing(Authentication token) {
        Client client = getClient();

        WebTarget webTarget = client
                .target(oAuth2ServiceProperties.getUserInfoUri())
                .queryParam(oAuth2ServiceProperties.getAccessTokenName(), (String)token.getCredentials());

        if (oAuth2ServiceProperties.getAdditionalInfoParams() != null) {
            for (Map.Entry<String, String> entry : oAuth2ServiceProperties.getAdditionalInfoParams().entrySet()) {
                webTarget = webTarget.queryParam(entry.getKey(), entry.getValue());
            }
        }

        return webTarget.request(MediaType.APPLICATION_JSON_TYPE)
                .get();
    }

    private Map<String, Object> getUserInfoMapFrom(Response response) {
        return response.readEntity(new GenericType<Map<String, Object>>() {});
    }

    private boolean isOkay(Response response) {
        return response != null && response.getStatusInfo().equals(Response.Status.OK);
    }

    /**
     * For caching the {@link Client} object.
     * @return The Jersey {@link Client} object to use.
     */
    protected Client getClient() {
        if (client == null) {
            client = ClientBuilder.newClient();
        }
        return client;
    }

    /**
     * Intended to be used for unit testing only.
     * @param client The {@link Client} to use. For unit tests allows the client to be mocked.
     */
    void setClient(Client client) {
        this.client = client;
    }

    public void setoAuth2ServiceProperties(OAuth2ServiceProperties oAuth2ServiceProperties) {
        this.oAuth2ServiceProperties = oAuth2ServiceProperties;
    }
}
