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
package org.owasp.dependencycheck.data.central;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Class of methods to search Maven Central via Central.
 *
 * @author colezlaw
 */
public class CentralSearch {

    /**
     * The URL for the Central service
     */
    private final URL rootURL;

    /**
     * Whether to use the Proxy when making requests
     */
    private final boolean useProxy;

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CentralSearch.class);

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param rootURL the URL of the repository on which searches should
     * execute. Only parameters are added to this (so it should end in /select)
     */
    public CentralSearch(URL rootURL) {
        this.rootURL = rootURL;
        if (null != Settings.getString(Settings.KEYS.PROXY_SERVER)) {
            useProxy = true;
            LOGGER.debug("Using proxy");
        } else {
            useProxy = false;
            LOGGER.debug("Not using proxy");
        }
    }

    /**
     * Searches the configured Central URL for the given sha1 hash. If the
     * artifact is found, a <code>MavenArtifact</code> is populated with the
     * GAV.
     *
     * @param sha1 the SHA-1 hash string for which to search
     * @return the populated Maven GAV.
     * @throws IOException if it's unable to connect to the specified repository
     * or if the specified artifact is not found.
     */
    public List<MavenArtifact> searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }
        List<MavenArtifact> result = null;
        final URL url = new URL(rootURL + String.format("?q=1:\"%s\"&wt=xml", sha1));

        LOGGER.debug("Searching Central url {}", url);

        // Determine if we need to use a proxy. The rules:
        // 1) If the proxy is set, AND the setting is set to true, use the proxy
        // 2) Otherwise, don't use the proxy (either the proxy isn't configured,
        // or proxy is specifically set to false)
        final HttpURLConnection conn = URLConnectionFactory.createHttpURLConnection(url, useProxy);

        conn.setDoOutput(true);

        // JSON would be more elegant, but there's not currently a dependency
        // on JSON, so don't want to add one just for this
        conn.addRequestProperty("Accept", "application/xml");
        conn.connect();

        if (conn.getResponseCode() == 200) {
            boolean missing = false;
            try {
                final DocumentBuilder builder = XmlUtils.buildSecureDocumentBuilder();
                final Document doc = builder.parse(conn.getInputStream());
                final XPath xpath = XPathFactory.newInstance().newXPath();
                final String numFound = xpath.evaluate("/response/result/@numFound", doc);
                if ("0".equals(numFound)) {
                    missing = true;
                } else {
                    result = new ArrayList<>();
                    final NodeList docs = (NodeList) xpath.evaluate("/response/result/doc", doc, XPathConstants.NODESET);
                    for (int i = 0; i < docs.getLength(); i++) {
                        final String g = xpath.evaluate("./str[@name='g']", docs.item(i));
                        LOGGER.trace("GroupId: {}", g);
                        final String a = xpath.evaluate("./str[@name='a']", docs.item(i));
                        LOGGER.trace("ArtifactId: {}", a);
                        final String v = xpath.evaluate("./str[@name='v']", docs.item(i));
                        NodeList attributes = (NodeList) xpath.evaluate("./arr[@name='ec']/str", docs.item(i), XPathConstants.NODESET);
                        boolean pomAvailable = false;
                        boolean jarAvailable = false;
                        for (int x = 0; x < attributes.getLength(); x++) {
                            final String tmp = xpath.evaluate(".", attributes.item(x));
                            if (".pom".equals(tmp)) {
                                pomAvailable = true;
                            } else if (".jar".equals(tmp)) {
                                jarAvailable = true;
                            }
                        }

                        attributes = (NodeList) xpath.evaluate("./arr[@name='tags']/str", docs.item(i), XPathConstants.NODESET);
                        boolean useHTTPS = false;
                        for (int x = 0; x < attributes.getLength(); x++) {
                            final String tmp = xpath.evaluate(".", attributes.item(x));
                            if ("https".equals(tmp)) {
                                useHTTPS = true;
                            }
                        }
                        LOGGER.trace("Version: {}", v);
                        result.add(new MavenArtifact(g, a, v, jarAvailable, pomAvailable, useHTTPS));
                    }
                }
            } catch (ParserConfigurationException | IOException | SAXException | XPathExpressionException e) {
                // Anything else is jacked up XML stuff that we really can't recover from well
                throw new IOException(e.getMessage(), e);
            }

            if (missing) {
                throw new FileNotFoundException("Artifact not found in Central");
            }
        } else {
            LOGGER.debug("Could not connect to Central received response code: {} {}",
                    conn.getResponseCode(), conn.getResponseMessage());
            throw new IOException("Could not connect to Central");
        }
        return result;
    }
}
