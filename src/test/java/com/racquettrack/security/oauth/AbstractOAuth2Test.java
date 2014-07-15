package com.racquettrack.security.oauth;

import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;

import javax.ws.rs.core.MediaType;

import org.mockito.Matchers;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;

/**
 * Helper class for initialising mocks for OAuth testing.
 *
 * @author paul.wheeler
 */
public class AbstractOAuth2Test {

    protected Client client = mock(Client.class);
    protected WebResource webResource = mock(WebResource.class);
    protected ClientResponse clientResponse = mock(ClientResponse.class);
    protected WebResource.Builder builder = mock(WebResource.Builder.class);

    /**
     * Initialise all the mocks necessary for mocking calls to the OAuth Provider.
     *
     * Allows subclasses to override behaviour. To run tests with different response values, individual tests
     * can always call Mockito again to override the data that will be returned.
     *
     * @param resourceUri  The resource URI that will be used in the call to  {@link Client#resource(String)}.
     * @param defaultResponse The defaultResponse data that will be returned by the call to {@link ClientResponse#getEntity(Class)}.
     */
    protected void initMocks(String resourceUri, String defaultResponse) {
        given(client.resource(resourceUri)).willReturn(webResource);
        given(webResource.queryParam(Matchers.anyString(), Matchers.anyString())).willReturn(webResource);
        given(webResource.accept(MediaType.APPLICATION_JSON_TYPE)).willReturn(builder);
        given(builder.type(MediaType.APPLICATION_FORM_URLENCODED)).willReturn(builder);
        given(builder.post(eq(ClientResponse.class), anyObject())).willReturn(clientResponse);
        given(builder.get(ClientResponse.class)).willReturn(clientResponse);
        given(clientResponse.getStatus()).willReturn(200);
        given(clientResponse.getClientResponseStatus()).willReturn(ClientResponse.Status.OK);

        given(clientResponse.getEntity(String.class)).willReturn(defaultResponse);
    }
}
