package com.racquettrack.security.oauth;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import org.mockito.Matchers;
import org.mockito.Mockito;

/**
 * Helper class for initialising mocks for OAuth testing.
 *
 * @author paul.wheeler
 */
public class AbstractOAuth2Test {

    protected Client client = Mockito.mock(Client.class);
    protected WebResource webResource = Mockito.mock(WebResource.class);
    protected ClientResponse clientResponse = Mockito.mock(ClientResponse.class);
    protected WebResource.Builder builder = Mockito.mock(WebResource.Builder.class);

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
        Mockito.when(client.resource(resourceUri)).thenReturn(webResource);
        Mockito.when(webResource.queryParam(Matchers.anyString(), Matchers.anyString())).thenReturn(webResource);
        Mockito.when(webResource.accept("application/json")).thenReturn(builder);
        Mockito.when(builder.get(ClientResponse.class)).thenReturn(clientResponse);
        Mockito.when(clientResponse.getStatus()).thenReturn(200);

        Mockito.when(clientResponse.getEntity(String.class)).thenReturn(defaultResponse);
    }
}
