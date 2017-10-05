package com.racquettrack.security.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockito.Matchers;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Map;

import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;

/**
 * Helper class for initialising mocks for OAuth testing.
 *
 * @author paul.wheeler
 */
public class AbstractOAuth2Test {

    protected Client client = mock(Client.class);
    protected WebTarget webTarget = mock(WebTarget.class);
    protected Response response = mock(Response.class);
    protected Invocation.Builder builder = mock(Invocation.Builder.class);
    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Initialise all the mocks necessary for mocking calls to the OAuth Provider.
     *
     * Allows subclasses to override behaviour. To run tests with different response values, individual tests
     * can always call Mockito again to override the data that will be returned.
     *
     * @param resourceUri  The resource URI that will be used in the call to  {@link Client#target(String)}.
     * @param defaultResponse The defaultResponse data that will be returned by the call to {@link Response#readEntity(Class)}.
     */
    protected void initMocks(String resourceUri, String defaultResponse) throws IOException {
        given(client.target(resourceUri)).willReturn(webTarget);
        given(webTarget.queryParam(Matchers.anyString(), Matchers.anyString())).willReturn(webTarget);
        given(webTarget.request(MediaType.APPLICATION_JSON_TYPE)).willReturn(builder);
        given(builder.post(anyObject())).willReturn(response);
        given(builder.get()).willReturn(response);
        given(response.getStatus()).willReturn(200);
        given(response.getStatusInfo()).willReturn(Response.Status.OK);

        TypeReference typeReference = new TypeReference<Map<String,Object>>(){};
        Map<String, Object> responseAsMap = objectMapper.readValue(defaultResponse, typeReference);

        given(response.readEntity(new GenericType<Map<String, Object>>() {})).willReturn(responseAsMap);
        given(response.readEntity(String.class)).willReturn(defaultResponse);
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }
}
