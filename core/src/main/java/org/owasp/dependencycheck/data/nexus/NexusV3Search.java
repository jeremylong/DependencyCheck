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
 * Copyright (c) 2023 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nexus;

import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Class of methods to search Nexus v3 repositories.
 *
 * @author Hans Aikema
 */
@ThreadSafe
public class NexusV3Search implements NexusSearch {

    /**
     * By default, NexusV3Search accepts only classifier-less artifacts.
     * <p>
     * This prevents, among others, sha1-collisions for empty jars on empty javadoc/sources jars.
     * See e.g. issues #5559 and #5118
     */
    private final Set<String> acceptedClassifiers = new HashSet<>();

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
    private static final Logger LOGGER = LoggerFactory.getLogger(NexusV3Search.class);

    /**
     * Creates a NexusV3Search for the given repository URL.
     *
     * @param settings the configured settings
     * @param useProxy flag indicating if the proxy settings should be used
     * @throws MalformedURLException thrown if the configured URL is
     *                               invalid
     */
    public NexusV3Search(Settings settings, boolean useProxy) throws MalformedURLException {
        this.settings = settings;
        this.useProxy = useProxy;
        this.acceptedClassifiers.add(null);
        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        LOGGER.debug("Nexus Search URL: {}", searchUrl);
        this.rootURL = new URL(searchUrl);

    }

    @Override
    public MavenArtifact searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }

        final List<MavenArtifact> collectedMatchingArtifacts = new ArrayList<>(1);

        String continuationToken = retrievePageAndAddMatchingArtifact(collectedMatchingArtifacts, sha1, null);
        while (continuationToken != null && collectedMatchingArtifacts.isEmpty()) {
            continuationToken = retrievePageAndAddMatchingArtifact(collectedMatchingArtifacts, sha1, continuationToken);
        }
        if (collectedMatchingArtifacts.isEmpty()) {
            throw new FileNotFoundException("Artifact not found in Nexus");
        } else {
            return collectedMatchingArtifacts.get(0);
        }
    }

    private String retrievePageAndAddMatchingArtifact(List<MavenArtifact> collectedMatchingArtifacts, String sha1, String continuationToken)
            throws IOException {
        final URL url;
        LOGGER.debug("Search with continuation token {}", continuationToken);
        if (continuationToken == null) {
            url = new URL(rootURL, String.format("v1/search/?sha1=%s",
                    sha1.toLowerCase()));
        } else {
            url = new URL(rootURL, String.format("v1/search/?sha1=%s&continuationToken=%s",
                    sha1.toLowerCase(), continuationToken));
        }

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

        conn.addRequestProperty("Accept", "application/json");
        conn.connect();
        final String nextContinuationToken;
        if (conn.getResponseCode() == 200) {
            nextContinuationToken = parseResponse(conn, sha1, collectedMatchingArtifacts);
        } else {
            LOGGER.debug("Could not connect to Nexus received response code: {} {}",
                    conn.getResponseCode(), conn.getResponseMessage());
            throw new IOException(String.format("Could not connect to Nexus, HTTP response code %d", conn.getResponseCode()));
        }
        return nextContinuationToken;
    }

    private String parseResponse(HttpURLConnection conn, String sha1, List<MavenArtifact> matchingArtifacts) throws IOException {
        try (InputStream in = new BufferedInputStream(conn.getInputStream());
             JsonReader jsonReader = Json.createReader(in)) {
            final JsonObject jsonResponse = jsonReader.readObject();
            final String continuationToken = jsonResponse.getString("continuationToken", null);
            final JsonArray components = jsonResponse.getJsonArray("items");
            boolean found = false;
            for (int i = 0; i < components.size() && !found; i++) {
                boolean jarFound = false;
                boolean pomFound = false;
                String downloadUrl = null;
                String groupId = null;
                String artifactId = null;
                String version = null;
                String pomUrl = null;

                final JsonObject component = components.getJsonObject(i);

                final String format = components.getJsonObject(0).getString("format", "unknown");
                if ("maven2".equals(format)) {
                    final JsonArray assets = component.getJsonArray("assets");
                    for (int j = 0; !found && j < assets.size(); j++) {
                        final JsonObject asset = assets.getJsonObject(j);
                        final JsonObject checksums = asset.getJsonObject("checksum");
                        final JsonObject maven2 = asset.getJsonObject("maven2");
                        if (maven2 != null
                                && "jar".equals(maven2.getString("extension", null))
                                && acceptedClassifiers.contains(maven2.getString("classifier", null))
                                && checksums != null && sha1.equals(checksums.getString("sha1", null))
                        ) {
                            downloadUrl = asset.getString("downloadUrl");
                            groupId = maven2.getString("groupId");
                            artifactId = maven2.getString("artifactId");
                            version = maven2.getString("version");

                            jarFound = true;
                        } else if (maven2 != null && "pom".equals(maven2.getString("extension"))) {
                            pomFound = true;
                            pomUrl = asset.getString("downloadUrl");
                        }
                        if (pomFound && jarFound) {
                            found = true;
                        }
                    }
                    if (found) {
                        matchingArtifacts.add(new MavenArtifact(groupId, artifactId, version, downloadUrl, pomUrl));
                    } else if (jarFound) {
                        final MavenArtifact ma = new MavenArtifact(groupId, artifactId, version, downloadUrl);
                        ma.setPomUrl(MavenArtifact.derivePomUrl(artifactId, version, downloadUrl));
                        matchingArtifacts.add(ma);
                        found = true;
                    }
                }
            }
            return continuationToken;
        }
    }

    @Override
    public boolean preflightRequest() {
        final HttpURLConnection conn;
        try {
            final URL url = new URL(rootURL, "v1/status");
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            conn = factory.createHttpURLConnection(url, useProxy);
            conn.addRequestProperty("Accept", "application/json");
            final String authHeader = buildHttpAuthHeaderValue();
            if (!authHeader.isEmpty()) {
                conn.addRequestProperty("Authorization", authHeader);
            }
            conn.connect();
            if (conn.getResponseCode() != 200) {
                LOGGER.warn("Expected 200 result from Nexus, got {}", conn.getResponseCode());
                return false;
            }
            if (conn.getContentLength() != 0) {
                LOGGER.warn("Expected empty OK response (content-length 0), got content-length {}", conn.getContentLength());
                return false;
            }
        } catch (IOException e) {
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
