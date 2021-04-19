/*
 * This file is part of dependency-check-core.
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
package org.owasp.dependencycheck.data.ossindex;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.sonatype.ossindex.service.client.OssindexClientConfiguration;
import org.sonatype.ossindex.service.client.transport.BasicAuthHelper;
import org.sonatype.ossindex.service.client.transport.HttpUrlConnectionTransport;
import org.sonatype.ossindex.service.client.transport.UserAgentSupplier;

/**
 * ODC connection transport is used instead of HttpUrlConnectionTransport
 * because the proxy information is already configured.
 *
 * @author Jeremy Long
 */
public class ODCConnectionTransport extends HttpUrlConnectionTransport {

    /**
     * The authorization header.
     */
    private static final String AUTHORIZATION = "Authorization";
    /**
     * The OSS Index client configuration.
     */
    private final OssindexClientConfiguration configuration;
    /**
     * The URL Connection factory.
     */
    private final URLConnectionFactory connectionFactory;
    /**
     * The user agent to send in the HTTP connection.
     */
    private final UserAgentSupplier userAgent;

    /**
     * Constructs a new transport object to connect to the OSS Index.
     *
     * @param settings the ODC settings
     * @param config the OSS client configuration
     * @param userAgent the user agent to send to OSS Index
     */
    public ODCConnectionTransport(Settings settings, OssindexClientConfiguration config, UserAgentSupplier userAgent) {
        super(userAgent);
        this.userAgent = userAgent;
        this.configuration = config;
        connectionFactory = new URLConnectionFactory(settings);
    }

    @Override
    protected HttpURLConnection connect(final URL url) throws IOException {
        final HttpURLConnection connection = connectionFactory.createHttpURLConnection(url);
        connection.setRequestProperty("User-Agent", userAgent.get());

        final String authorization = BasicAuthHelper.authorizationHeader(configuration.getAuthConfiguration());
        if (authorization != null) {
            connection.setRequestProperty(AUTHORIZATION, authorization);
        }
        return connection;
    }

}
