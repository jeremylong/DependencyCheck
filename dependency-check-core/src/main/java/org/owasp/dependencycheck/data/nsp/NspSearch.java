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
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nsp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue.ValueType;
import static org.owasp.dependencycheck.analyzer.NspAnalyzer.DEFAULT_URL;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;

/**
 * Class of methods to search via Node Security Platform.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NspSearch {

    /**
     * The URL for the public NSP check API.
     */
    private final URL nspCheckUrl;

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
    private static final Logger LOGGER = LoggerFactory.getLogger(NspSearch.class);

    /**
     * Creates a NspSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @throws java.net.MalformedURLException thrown if the configured URL is
     * invalid
     */
    public NspSearch(Settings settings) throws MalformedURLException {
        final String searchUrl = settings.getString(Settings.KEYS.ANALYZER_NSP_URL, DEFAULT_URL);
        LOGGER.debug("NSP Search URL: {}", searchUrl);
        this.nspCheckUrl = new URL(searchUrl);
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
     * Submits the package.json file to the NSP public /check API and returns a
     * list of zero or more Advisories.
     *
     * @param packageJson the package.json file retrieved from the Dependency
     * @return a List of zero or more Advisory object
     * @throws AnalysisException if Node Security Platform is unable to analyze
     * the package
     * @throws IOException if it's unable to connect to Node Security Platform
     */
    public List<Advisory> submitPackage(JsonObject packageJson) throws AnalysisException, IOException {
        try {
            final List<Advisory> result = new ArrayList<>();
            final byte[] packageDatabytes = packageJson.toString().getBytes(StandardCharsets.UTF_8);
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            final HttpURLConnection conn = factory.createHttpURLConnection(nspCheckUrl, useProxy);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("X-NSP-VERSION", "2.6.2");
            conn.setRequestProperty("Content-Type", "application/json");
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
                        final JsonArray array = jsonReader.readArray();

                        if (array != null) {
                            for (int i = 0; i < array.size(); i++) {
                                final JsonObject object = array.getJsonObject(i);
                                final Advisory advisory = new Advisory();
                                advisory.setId(object.getInt("id"));
                                advisory.setUpdatedAt(object.getString("updated_at", null));
                                advisory.setCreatedAt(object.getString("created_at", null));
                                advisory.setPublishDate(object.getString("publish_date", null));
                                advisory.setOverview(object.getString("overview"));
                                advisory.setRecommendation(object.getString("recommendation", null));
                                advisory.setCvssVector(object.getString("cvss_vector", null));

                                if (object.get("cvss_score").getValueType() != ValueType.NULL) {
                                    advisory.setCvssScore(Float.parseFloat(object.getJsonNumber("cvss_score").toString()));
                                } else {
                                    advisory.setCvssScore(-1);
                                }

                                advisory.setModule(object.getString("module", null));
                                advisory.setVersion(object.getString("version", null));
                                advisory.setVulnerableVersions(object.getString("vulnerable_versions", null));
                                advisory.setPatchedVersions(object.getString("patched_versions", null));
                                advisory.setTitle(object.getString("title", null));
                                advisory.setAdvisory(object.getString("advisory", null));

                                final JsonArray jsonPath = object.getJsonArray("path");
                                final List<String> stringPath = new ArrayList<>();
                                for (int j = 0; j < jsonPath.size(); j++) {
                                    stringPath.add(jsonPath.getString(j));
                                }
                                advisory.setPath(stringPath.toArray(new String[stringPath.size()]));

                                result.add(advisory);
                            }
                        }
                    }
                    break;

                case 400:
                    LOGGER.debug("Invalid payload submitted to Node Security Platform. Received response code: {} {}",
                            conn.getResponseCode(), conn.getResponseMessage());
                    throw new AnalysisException("Could not perform NSP analysis. Invalid payload submitted to Node Security Platform.");
                default:
                    LOGGER.debug("Could not connect to Node Security Platform. Received response code: {} {}",
                            conn.getResponseCode(), conn.getResponseMessage());
                    throw new IOException("Could not connect to Node Security Platform");
            }
            return result;
        } catch (IOException ex) {
            if (ex instanceof javax.net.ssl.SSLHandshakeException
                    && ex.getMessage().contains("unable to find valid certification path to requested target")) {
                final String msg = String.format("Unable to connect to '%s' - the Java trust store does not contain a trusted root for the cert. "
                        + " Please see https://github.com/jeremylong/InstallCert for one method of updating the trusted certificates.", nspCheckUrl);
                throw new URLConnectionFailureException(msg, ex);
            }
            throw ex;
        }
    }
}
