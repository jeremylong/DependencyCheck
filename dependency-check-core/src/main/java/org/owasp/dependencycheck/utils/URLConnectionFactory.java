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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;

/**
 * A URLConnection Factory to create new connections. This encapsulates several configuration checks to ensure that the
 * connection uses the correct proxy settings.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class URLConnectionFactory {

    /**
     * Private constructor for this factory.
     */
    private URLConnectionFactory() {
    }

    /**
     * Utility method to create an HttpURLConnection. If the application is configured to use a proxy this method will
     * retrieve the proxy settings and use them when setting up the connection.
     *
     * @param url the url to connect to
     * @return an HttpURLConnection
     * @throws URLConnectionFailureException thrown if there is an exception
     */
    public static HttpURLConnection createHttpURLConnection(URL url) throws URLConnectionFailureException {
        HttpURLConnection conn = null;
        Proxy proxy = null;
        final String proxyUrl = Settings.getString(Settings.KEYS.PROXY_URL);
        try {
            if (proxyUrl != null) {
                final int proxyPort = Settings.getInt(Settings.KEYS.PROXY_PORT);
                final SocketAddress addr = new InetSocketAddress(proxyUrl, proxyPort);

                final String username = Settings.getString(Settings.KEYS.PROXY_USERNAME);
                final String password = Settings.getString(Settings.KEYS.PROXY_PASSWORD);
                if (username != null && password != null) {
                    final Authenticator auth = new Authenticator() {
                        @Override
                        public PasswordAuthentication getPasswordAuthentication() {
                            if (getRequestorType().equals(Authenticator.RequestorType.PROXY)) {
                                return new PasswordAuthentication(username, password.toCharArray());
                            }
                            return super.getPasswordAuthentication();
                        }
                    };
                    Authenticator.setDefault(auth);
                }

                proxy = new Proxy(Proxy.Type.HTTP, addr);
                conn = (HttpURLConnection) url.openConnection(proxy);
            } else {
                conn = (HttpURLConnection) url.openConnection();
            }
            final int timeout = Settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 60000);
            conn.setConnectTimeout(timeout);
        } catch (IOException ex) {
            if (conn != null) {
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
            }
            throw new URLConnectionFailureException("Error getting connection.", ex);
        }
        return conn;
    }

    /**
     * Utility method to create an HttpURLConnection. The use of a proxy here is optional as there may be cases where a
     * proxy is configured but we don't want to use it (for example, if there's an internal repository configured)
     *
     * @param url the url to connect to
     * @param proxy whether to use the proxy (if configured)
     * @return a newly constructed HttpURLConnection
     * @throws URLConnectionFailureException thrown if there is an exception
     */
    public static HttpURLConnection createHttpURLConnection(URL url, boolean proxy) throws URLConnectionFailureException {
        if (proxy) {
            return createHttpURLConnection(url);
        }
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) url.openConnection();
            final int timeout = Settings.getInt(Settings.KEYS.CONNECTION_TIMEOUT, 60000);
            conn.setConnectTimeout(timeout);
        } catch (IOException ioe) {
            throw new URLConnectionFailureException("Error getting connection.", ioe);
        }
        return conn;
    }
}
