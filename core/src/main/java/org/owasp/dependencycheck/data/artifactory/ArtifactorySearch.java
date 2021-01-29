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
 * Copyright (c) 2018 Nicolas Henneaux. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.artifactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Checksum;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

/**
 * Class of methods to search Artifactory for hashes and determine Maven GAV
 * from there.
 *
 * Data classes copied from JFrog's artifactory-client-java project.
 *
 * @author nhenneaux
 */
@ThreadSafe
@SuppressWarnings("squid:S2647")
public class ArtifactorySearch {

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ArtifactorySearch.class);

    /**
     * Pattern to match the path returned by the Artifactory AQL API.
     */
    private static final Pattern PATH_PATTERN = Pattern.compile("^/(?<groupId>.+)/(?<artifactId>[^/]+)/(?<version>[^/]+)/[^/]+$");
    /**
     * Extracted duplicateArtifactorySearchIT.java comment.
     */
    private static final String WHILE_ACTUAL_IS = " while actual is ";
    /**
     * The URL for the Central service.
     */
    private final String rootURL;

    /**
     * Whether to use the Proxy when making requests.
     */
    private final boolean useProxy;

    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Search result reader
     */
    private final ObjectReader objectReader;

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param settings the configured settings
     */
    public ArtifactorySearch(Settings settings) {
        this.settings = settings;

        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_ARTIFACTORY_URL);

        this.rootURL = searchUrl;
        LOGGER.debug("Artifactory Search URL {}", searchUrl);

        if (null != settings.getString(Settings.KEYS.PROXY_SERVER)) {
            boolean useProxySettings = false;
            try {
                useProxySettings = settings.getBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY);
            } catch (InvalidSettingException e) {
                LOGGER.error("Settings {} is invalid, only, true/false is valid", Settings.KEYS.ANALYZER_ARTIFACTORY_USES_PROXY, e);
            }
            this.useProxy = useProxySettings;
            LOGGER.debug("Using proxy? {}", useProxy);
        } else {
            useProxy = false;
            LOGGER.debug("Not using proxy");
        }

        objectReader = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false).readerFor(FileImpl.class);
    }

    /**
     * Searches the configured Central URL for the given hash (MD5, SHA1 and
     * SHA256). If the artifact is found, a <code>MavenArtifact</code> is
     * populated with the GAV.
     *
     * @param dependency the dependency for which to search (search is based on
     * hashes)
     * @return the populated Maven GAV.
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException if it's unable to connect to the specified repository
     */
    public List<MavenArtifact> search(Dependency dependency) throws IOException {

        final String sha1sum = dependency.getSha1sum();
        final URL url = buildUrl(sha1sum);
        final HttpURLConnection conn = connect(url);
        final int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            return processResponse(dependency, conn);
        }
        throw new IOException("Could not connect to Artifactory " + url + " (" + responseCode + "): " + conn.getResponseMessage());

    }

    /**
     * Makes an connection to the given URL.
     *
     * @param url the URL to connect to
     * @return the HTTP URL Connection
     * @throws IOException thrown if there is an error making the connection
     */
    private HttpURLConnection connect(URL url) throws IOException {
        LOGGER.debug("Searching Artifactory url {}", url);

        // Determine if we need to use a proxy. The rules:
        // 1) If the proxy is set, AND the setting is set to true, use the proxy
        // 2) Otherwise, don't use the proxy (either the proxy isn't configured,
        // or proxy is specifically set to false)
        final URLConnectionFactory factory = new URLConnectionFactory(settings);
        final HttpURLConnection conn = factory.createHttpURLConnection(url, useProxy);
        conn.setDoOutput(true);

        conn.addRequestProperty("X-Result-Detail", "info");

        final String username = settings.getString(Settings.KEYS.ANALYZER_ARTIFACTORY_API_USERNAME);
        final String apiToken = settings.getString(Settings.KEYS.ANALYZER_ARTIFACTORY_API_TOKEN);
        if (username != null && apiToken != null) {
            final String userpassword = username + ":" + apiToken;
            final String encodedAuthorization = Base64.getEncoder().encodeToString(userpassword.getBytes(StandardCharsets.UTF_8));
            conn.addRequestProperty("Authorization", "Basic " + encodedAuthorization);
        } else {
            final String bearerToken = settings.getString(Settings.KEYS.ANALYZER_ARTIFACTORY_BEARER_TOKEN);
            if (bearerToken != null) {
                conn.addRequestProperty("Authorization", "Bearer " + bearerToken);
            }
        }

        conn.connect();
        return conn;
    }

    /**
     * Constructs the URL using the SHA1 checksum.
     *
     * @param sha1sum the SHA1 checksum
     * @return the API URL to search for the given checksum
     * @throws MalformedURLException thrown if the URL is malformed
     */
    private URL buildUrl(String sha1sum) throws MalformedURLException {
        // TODO Investigate why sha256 parameter is not working
        // API defined https://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-ChecksumSearch
        return new URL(rootURL + "/api/search/checksum?sha1=" + sha1sum);
    }

    /**
     * Process the Artifactory response.
     *
     * @param dependency the dependency
     * @param conn the HTTP URL Connection
     * @return a list of the Maven Artifact information
     * @throws IOException thrown if there is an I/O error
     */
    protected List<MavenArtifact> processResponse(Dependency dependency, HttpURLConnection conn) throws IOException {
        final List<MavenArtifact> result = new ArrayList<>();

        try (InputStreamReader streamReader = new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8);
                JsonParser parser = objectReader.getFactory().createParser(streamReader)) {

            if (init(parser) && parser.nextToken() == com.fasterxml.jackson.core.JsonToken.START_OBJECT) {
                // at least one result
                do {
                    final FileImpl file = objectReader.readValue(parser);

                    checkHashes(dependency, file.getChecksums());

                    final Matcher pathMatcher = PATH_PATTERN.matcher(file.getPath());
                    if (!pathMatcher.matches()) {
                        throw new IllegalStateException("Cannot extract the Maven information from the path "
                                + "retrieved in Artifactory " + file.getPath());
                    }

                    final String groupId = pathMatcher.group("groupId").replace('/', '.');
                    final String artifactId = pathMatcher.group("artifactId");
                    final String version = pathMatcher.group("version");

                    result.add(new MavenArtifact(groupId, artifactId, version, file.getDownloadUri(),
                            MavenArtifact.derivePomUrl(artifactId, version, file.getDownloadUri())));

                } while (parser.nextToken() == com.fasterxml.jackson.core.JsonToken.START_OBJECT);
            } else {
                throw new FileNotFoundException("Artifact " + dependency + " not found in Artifactory");
            }
        }

        return result;
    }

    protected boolean init(JsonParser parser) throws IOException {
        com.fasterxml.jackson.core.JsonToken nextToken = parser.nextToken();
        if (nextToken != com.fasterxml.jackson.core.JsonToken.START_OBJECT) {
            throw new IOException("Expected " + com.fasterxml.jackson.core.JsonToken.START_OBJECT + ", got " + nextToken);
        }

        do {
            nextToken = parser.nextToken();
            if (nextToken == null) {
                break;
            }

            if (nextToken.isStructStart()) {
                if (nextToken == com.fasterxml.jackson.core.JsonToken.START_ARRAY && "results".equals(parser.currentName())) {
                    return true;
                } else {
                    parser.skipChildren();
                }
            }
        } while (true);

        return false;
    }

    /**
     * Validates the hashes of the dependency.
     *
     * @param dependency the dependency
     * @param checksums the collection of checksums (md5, sha1, sha256)
     * @throws FileNotFoundException thrown if one of the checksums does not
     * match
     */
    private void checkHashes(Dependency dependency, ChecksumsImpl checksums) throws FileNotFoundException {
        final String md5sum = dependency.getMd5sum();
        if (!checksums.getMd5().equals(md5sum)) {
            throw new FileNotFoundException("Artifact found by API is not matching the md5 "
                    + "of the artifact (repository hash is " + checksums.getMd5() + WHILE_ACTUAL_IS + md5sum + ") !");
        }
        final String sha1sum = dependency.getSha1sum();
        if (!checksums.getSha1().equals(sha1sum)) {
            throw new FileNotFoundException("Artifact found by API is not matching the SHA1 "
                    + "of the artifact (repository hash is " + checksums.getSha1() + WHILE_ACTUAL_IS + sha1sum + ") !");
        }
        final String sha256sum = dependency.getSha256sum();
        if (checksums.getSha256() != null && !checksums.getSha256().equals(sha256sum)) {
            throw new FileNotFoundException("Artifact found by API is not matching the SHA-256 "
                    + "of the artifact (repository hash is " + checksums.getSha256() + WHILE_ACTUAL_IS + sha256sum + ") !");
        }
    }

    /**
     * Performs a pre-flight request to ensure the Artifactory service is
     * reachable.
     *
     * @return <code>true</code> if Artifactory could be reached; otherwise
     * <code>false</code>.
     */
    public boolean preflightRequest() {
        try {
            final URL url = buildUrl(Checksum.getSHA1Checksum(UUID.randomUUID().toString()));
            final HttpURLConnection connection = connect(url);
            if (connection.getResponseCode() != 200) {
                LOGGER.warn("Expected 200 result from Artifactory ({}), got {}", url, connection.getResponseCode());
                return false;
            }
            return true;
        } catch (IOException e) {
            LOGGER.error("Cannot connect to Artifactory", e);
            return false;
        }

    }
}
