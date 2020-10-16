/*
 * This file is part of dependency-check-utils.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import io.netty.handler.codec.http.HttpResponseStatus;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Rule;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

/**
 *
 * @author Jeremy Long
 */
public class URLConnectionFactoryIT extends BaseTest {

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this);

    private MockServerClient mockServerClient;

    @Before
    public void reset() {
        mockServerClient.reset();
    }

    /**
     * Test of createHttpURLConnection method, of class URLConnectionFactory to
     * validate if a basic authorization header is added.
     */
    @Test
    public void testCreateHttpURLConnection_Authorization_unauthorized() throws Exception {
        mockServerClient.when(HttpRequest.request().withMethod("GET")
                .withHeader("Authorization", "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
                .withPath("/secure/resource.xml"), Times.once())
                .respond(HttpResponse.response().withBody("ok").withStatusCode(200));
        mockServerClient.when(HttpRequest.request().withMethod("GET")
                .withPath("/secure/resource.xml"), Times.once())
                .respond(HttpResponse.response().withBody("Unauthorized").withStatusCode(401));

        URL url = new URL("http://localhost:"
                + mockServerClient.remoteAddress().getPort()
                + "/secure/resource.xml");
        URLConnectionFactory instance = new URLConnectionFactory(getSettings());
        HttpURLConnection conn = instance.createHttpURLConnection(url);
        try {
            conn.connect();
        } catch (IOException ex) {

        }
        assertEquals(HttpResponseStatus.UNAUTHORIZED.code(), conn.getResponseCode());
        conn.disconnect();
    }

    /**
     * Test of createHttpURLConnection method, of class URLConnectionFactory to
     * validate if a basic authorization header is added.
     */
    @Test
    public void testCreateHttpURLConnection_Authorization() throws Exception {
        mockServerClient.when(HttpRequest.request().withMethod("GET")
                .withHeader("Authorization", "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
                .withPath("/secure/resource.xml"), Times.once())
                .respond(HttpResponse.response().withBody("ok").withStatusCode(200));
        mockServerClient.when(HttpRequest.request().withMethod("GET")
                .withPath("/secure/resource.xml"), Times.once())
                .respond(HttpResponse.response().withBody("Unauthorized").withStatusCode(401));

        URL url = new URL("http://username:password@localhost:"
                + mockServerClient.remoteAddress().getPort()
                + "/secure/resource.xml");
        URLConnectionFactory instance = new URLConnectionFactory(getSettings());
        HttpURLConnection conn = instance.createHttpURLConnection(url);
        try {
            conn.connect();
        } catch (IOException ex) {

        }
        assertEquals(HttpResponseStatus.OK.code(), conn.getResponseCode());
        conn.disconnect();
    }
}
