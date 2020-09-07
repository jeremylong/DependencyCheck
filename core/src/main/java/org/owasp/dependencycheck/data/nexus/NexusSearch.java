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
package org.owasp.dependencycheck.data.nexus;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.owasp.dependencycheck.utils.Settings;

import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Class of methods to search Nexus repositories.
 *
 * @author colezlaw
 */
@ThreadSafe
public class NexusSearch {

    /**
     * The root URL for the Nexus repository service.
     */
    private final URL rootURL;

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
    private static final Logger LOGGER = LoggerFactory.getLogger(NexusSearch.class);

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @param useProxy flag indicating if the proxy settings should be used
     * @throws java.net.MalformedURLException thrown if the configured URL is
     * invalid
     */
    public NexusSearch(Settings settings, boolean useProxy) throws MalformedURLException {
        this.settings = settings;
        this.useProxy = useProxy;

        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        LOGGER.debug("Nexus Search URL: {}", searchUrl);
        this.rootURL = new URL(searchUrl);

    }

    /**
     * Searches the configured Nexus repository for the given sha1 hash. If the
     * artifact is found, a <code>MavenArtifact</code> is populated with the
     * coordinate information.
     *
     * @param sha1 The SHA-1 hash string for which to search
     * @return the populated Maven coordinates
     * @throws IOException if it's unable to connect to the specified repository
     * or if the specified artifact is not found.
     */
    public MavenArtifact searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }

        final URL url = new URL(rootURL, String.format("identify/sha1/%s",
                sha1.toLowerCase()));

        LOGGER.debug("Searching Nexus url {}", url);

        // Determine if we need to use a proxy. The rules:
        // 1) If the proxy is set, AND the setting is set to true, use the proxy
        // 2) Otherwise, don't use the proxy (either the proxy isn't configured,
        // or proxy is specifically set to false
        final HttpURLConnection conn;
        final URLConnectionFactory factory = new URLConnectionFactory(settings);
        conn = factory.createHttpURLConnection(url, useProxy);
        conn.setDoOutput(true);
        final String authHeader = buildHttpAuthHeaderValue();
        if (!authHeader.isEmpty()) {
            conn.addRequestProperty("Authorization", authHeader);
        }

        // JSON would be more elegant, but there's not currently a dependency
        // on JSON, so don't want to add one just for this
        conn.addRequestProperty("Accept", "application/xml");
        conn.connect();

        switch (conn.getResponseCode()) {
            case 200:
                try {
                    final DocumentBuilder builder = XmlUtils.buildSecureDocumentBuilder();
                    final Document doc = builder.parse(conn.getInputStream());
                    final XPath xpath = XPathFactory.newInstance().newXPath();
                    final String groupId = xpath
                            .evaluate(
                                    "/org.sonatype.nexus.rest.model.NexusArtifact/groupId",
                                    doc);
                    final String artifactId = xpath.evaluate(
                            "/org.sonatype.nexus.rest.model.NexusArtifact/artifactId",
                            doc);
                    final String version = xpath
                            .evaluate(
                                    "/org.sonatype.nexus.rest.model.NexusArtifact/version",
                                    doc);
                    final String link = xpath
                            .evaluate(
                                    "/org.sonatype.nexus.rest.model.NexusArtifact/artifactLink",
                                    doc);
                    final String pomLink = xpath
                            .evaluate(
                                    "/org.sonatype.nexus.rest.model.NexusArtifact/pomLink",
                                    doc);
                    final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version);
                    if (link != null && !link.isEmpty()) {
                        ma.setArtifactUrl(link);
                    }
                    if (pomLink != null && !pomLink.isEmpty()) {
                        ma.setPomUrl(pomLink);
                    }
                    return ma;
                } catch (ParserConfigurationException | IOException | SAXException | XPathExpressionException e) {
                    // Anything else is jacked-up XML stuff that we really can't recover
                    // from well
                    throw new IOException(e.getMessage(), e);
                }
            case 404:
                throw new FileNotFoundException("Artifact not found in Nexus");
            default:
                LOGGER.debug("Could not connect to Nexus received response code: {} {}",
                        conn.getResponseCode(), conn.getResponseMessage());
                throw new IOException("Could not connect to Nexus");
        }
    }

    /**
     * Do a preflight request to see if the repository is actually working.
     *
     * @return whether the repository is listening and returns the /status URL
     * correctly
     */
    public boolean preflightRequest() {
        final HttpURLConnection conn;
        try {
            final URL url = new URL(rootURL, "status");
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            conn = factory.createHttpURLConnection(url, useProxy);
            conn.addRequestProperty("Accept", "application/xml");
            final String authHeader = buildHttpAuthHeaderValue();
            if (!authHeader.isEmpty()) {
                conn.addRequestProperty("Authorization", authHeader);
            }
            conn.connect();
            if (conn.getResponseCode() != 200) {
                LOGGER.warn("Expected 200 result from Nexus, got {}", conn.getResponseCode());
                return false;
            }
            final DocumentBuilder builder = XmlUtils.buildSecureDocumentBuilder();

            final Document doc = builder.parse(conn.getInputStream());
            if (!"status".equals(doc.getDocumentElement().getNodeName())) {
                LOGGER.warn("Expected root node name of status, got {}", doc.getDocumentElement().getNodeName());
                return false;
            }
        } catch (IOException | ParserConfigurationException | SAXException e) {
            LOGGER.warn("Pre-flight request to Nexus failed: ", e);
            return false;
        }
        return true;
    }

    /**
     * Constructs the base64 encoded basic authentication header value.
     *
     * @return the base64 encoded basic authentication header value
     */
    private String buildHttpAuthHeaderValue() {
        final String user = settings.getString(Settings.KEYS.ANALYZER_NEXUS_USER, "");
        final String pass = settings.getString(Settings.KEYS.ANALYZER_NEXUS_PASSWORD, "");
        String result = "";
        if (user.isEmpty() || pass.isEmpty()) {
            LOGGER.debug("Skip authentication as user and/or password for nexus is empty");
        } else {
            final String auth = user + ':' + pass;
            final String base64Auth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
            result = "Basic " + base64Auth;
        }
        return result;
    }
}
