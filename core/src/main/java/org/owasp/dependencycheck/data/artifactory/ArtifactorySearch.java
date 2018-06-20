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
package org.owasp.dependencycheck.data.artifactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class of methods to search Artifactory for hashes and determine Maven GAV from there.
 *
 * @author nhenneaux
 */
@ThreadSafe
public class ArtifactorySearch {

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ArtifactorySearch.class);

    private static final Pattern PATH_PATTERN = Pattern.compile("^/(?<groupId>.+)/(?<artifactId>[^/]+)/(?<version>[^/]+)/[^/]+$");
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
    }

    /**
     * Searches the configured Central URL for the given hash (MD5, SHA1 and SHA256). If the
     * artifact is found, a <code>MavenArtifact</code> is populated with the
     * GAV.
     *
     * @param dependency the dependency for which to search (search is based on hashes)
     * @return the populated Maven GAV.
     * @throws FileNotFoundException if the specified artifact is not found
     * @throws IOException           if it's unable to connect to the specified repository
     */
    public List<MavenArtifact> search(Dependency dependency) throws IOException {

        final URL url = new URL(rootURL + "/api/search/checksum?sha1=" + dependency.getSha1sum());
        LOGGER.debug("Searching Artifactory url {}", url);

        // Determine if we need to use a proxy. The rules:
        // 1) If the proxy is set, AND the setting is set to true, use the proxy
        // 2) Otherwise, don't use the proxy (either the proxy isn't configured,
        // or proxy is specifically set to false)
        final URLConnectionFactory factory = new URLConnectionFactory(settings);
        final HttpURLConnection conn = factory.createHttpURLConnection(url, useProxy);
        conn.setDoOutput(true);
        conn.addRequestProperty("X-Result-Detail", "info");
        // TODO what is the best way to retrieve credentials to connect to Artifactory?
        conn.addRequestProperty("Authorization", "Bearer " + System.getenv("artifactory.authentication.bearer.token"));
        conn.connect();
        final int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            return processResponse(dependency, conn);
        }
        throw new IOException("Could not connect to Artifactory " + url + " (" + responseCode + "): " + conn.getResponseMessage());

    }


    List<MavenArtifact> processResponse(Dependency dependency, HttpURLConnection conn) throws IOException {
        final JsonObject asJsonObject = new JsonParser().parse(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)).getAsJsonObject();
        final JsonArray results = asJsonObject.getAsJsonArray("results");
        final int numFound = results.size();
        if (numFound == 0) {
            throw new FileNotFoundException("Artifact " + dependency + " not found in Artifactory");
        }


        final String sha1sum = dependency.getSha1sum();
        final String sha256sum = dependency.getSha256sum();
        final String md5sum = dependency.getMd5sum();

        final List<MavenArtifact> result = new ArrayList<>(numFound);
        for (JsonElement jsonElement : results) {

            final JsonObject checksumList = jsonElement.getAsJsonObject().getAsJsonObject("checksums");
            final String sha1 = checksumList.getAsJsonPrimitive("sha1").getAsString();
            final JsonPrimitive sha256Primitive = checksumList.getAsJsonPrimitive("sha256");
            final String sha256 = sha256Primitive == null ? null : sha256Primitive.getAsString();
            final String md5 = checksumList.getAsJsonPrimitive("md5").getAsString();

            if (!md5.equals(md5sum)) {
                throw new FileNotFoundException("Artifact found by API is not matching the md5 of the artifact (repository hash is " + md5 + WHILE_ACTUAL_IS + md5sum + ") !");
            }
            if (!sha1.equals(sha1sum)) {
                throw new FileNotFoundException("Artifact found by API is not matching the SHA1 of the artifact (repository hash is " + sha1 + WHILE_ACTUAL_IS + sha1sum + ") !");
            }
            if (sha256 != null && !sha256.equals(sha256sum)) {
                throw new FileNotFoundException("Artifact found by API is not matching the SHA-256 of the artifact (repository hash is " + sha256 + WHILE_ACTUAL_IS + sha256sum + ") !");
            }

            final String downloadUri = jsonElement.getAsJsonObject().getAsJsonPrimitive("downloadUri").getAsString();

            final String path = jsonElement.getAsJsonObject().getAsJsonPrimitive("path").getAsString();

            final Matcher pathMatcher = PATH_PATTERN.matcher(path);
            if (!pathMatcher.matches()) {
                throw new IllegalStateException("Cannot extract the Maven information from the apth retrieved in Artifactory " + path);
            }
            final String groupId = pathMatcher.group("groupId").replace('/', '.');
            final String artifactId = pathMatcher.group("artifactId");
            final String version = pathMatcher.group("version");

            result.add(new MavenArtifact(groupId, artifactId, version, downloadUri));
        }

        return result;
    }

}
