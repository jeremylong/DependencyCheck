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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import org.json.JSONObject;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import static org.owasp.dependencycheck.analyzer.NodeAuditAnalyzer.DEFAULT_URL;
import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;

/**
 * Class of methods to search via Node Audit API.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NodeAuditSearch {

    /**
     * The URL for the public Node Audit API.
     */
    private final URL nodeAuditUrl;

    /**
     * Whether to use the Proxy when making requests.
     */
    private final boolean useProxy;
    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NodeAuditSearch.class);

    /**
     * Creates a NodeAuditSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @throws java.net.MalformedURLException thrown if the configured URL is
     * invalid
     */
    public NodeAuditSearch(Settings settings) throws MalformedURLException {
        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NODE_AUDIT_URL, DEFAULT_URL);
        LOGGER.debug("Node Audit Search URL: {}", searchUrl);
        this.nodeAuditUrl = new URL(searchUrl);
        this.settings = settings;
        if (null != settings.getString(Settings.KEYS.PROXY_SERVER)) {
            useProxy = true;
            LOGGER.debug("Using proxy");
        } else {
            useProxy = false;
            LOGGER.debug("Not using proxy");
        }
    }

    /**
     * Submits the package.json file to the Node Audit API and returns a
     * list of zero or more Advisories.
     *
     * @param packageJson the package.json file retrieved from the Dependency
     * @return a List of zero or more Advisory object
     * @throws SearchException if Node Audit API is unable to analyze
     * the package
     * @throws IOException if it's unable to connect to Node Audit API
     */
    public List<Advisory> submitPackage(JsonObject packageJson) throws SearchException, IOException {
        try {
            final List<Advisory> result = new ArrayList<>();
            final byte[] packageDatabytes = packageJson.toString().getBytes(StandardCharsets.UTF_8);
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            final HttpURLConnection conn = factory.createHttpURLConnection(nodeAuditUrl, useProxy);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("user-agent", "npm/6.1.0 node/v10.5.0 linux x64");
            conn.setRequestProperty("npm-in-ci", "false");
            conn.setRequestProperty("npm-scope", "");
            conn.setRequestProperty("npm-session", generateRandomSession());
            conn.setRequestProperty("content-type", "application/json");
            conn.setRequestProperty("Content-Length", Integer.toString(packageDatabytes.length));
            conn.connect();

            try (OutputStream os = new BufferedOutputStream(conn.getOutputStream())) {
                os.write(packageDatabytes);
                os.flush();
            }

            switch (conn.getResponseCode()) {
                case 200:
                    try (InputStream in = new BufferedInputStream(conn.getInputStream());
                            JsonReader jsonReader = Json.createReader(in)) {
                        final JSONObject jsonResponse = new org.json.JSONObject(jsonReader.readObject().toString());
                        final NpmAuditParser parser = new NpmAuditParser();
                        return parser.parse(jsonResponse);
                    }
                case 400:
                    LOGGER.debug("Invalid payload submitted to Node Audit API. Received response code: {} {}",
                            conn.getResponseCode(), conn.getResponseMessage());
                    throw new SearchException("Could not perform Node Audit analysis. Invalid payload submitted to Node Audit API.");
                default:
                    LOGGER.debug("Could not connect to Node Audit API. Received response code: {} {}",
                            conn.getResponseCode(), conn.getResponseMessage());
                    throw new IOException("Could not connect to Node Audit API");
            }
        } catch (IOException ex) {
            if (ex instanceof javax.net.ssl.SSLHandshakeException
                    && ex.getMessage().contains("unable to find valid certification path to requested target")) {
                final String msg = String.format("Unable to connect to '%s' - the Java trust store does not contain a trusted root for the cert. "
                        + " Please see https://github.com/jeremylong/InstallCert for one method of updating the trusted certificates.", nodeAuditUrl);
                throw new URLConnectionFailureException(msg, ex);
            }
            throw ex;
        }
    }

    /**
     * Generates a random 16 character lower-case hex string.
     */
    private String generateRandomSession() {
        final int length = 16;
        final SecureRandom r = new SecureRandom();
        final StringBuilder sb = new StringBuilder();
        while(sb.length() < length){
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, length);
    }
}
