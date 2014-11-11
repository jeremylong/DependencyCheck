package org.owasp.dependencycheck.data.central;

import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

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
    private boolean useProxy;

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = Logger.getLogger(CentralSearch.class.getName());

    /**
     * Determines whether we'll continue using the analyzer. If there's some sort of HTTP failure, we'll disable the
     * analyzer.
     */
    private boolean isEnabled = true;

    /**
     * Creates a NexusSearch for the given repository URL.
     *
     * @param rootURL the URL of the repository on which searches should execute. Only parameters are added to this (so
     * it should end in /select)
     */
    public CentralSearch(URL rootURL) {
        this.rootURL = rootURL;
        if (null != Settings.getString(Settings.KEYS.PROXY_SERVER)) {
            useProxy = true;
            LOGGER.fine("Using proxy");
        } else {
            useProxy = false;
            LOGGER.fine("Not using proxy");
        }
    }

    /**
     * Searches the configured Central URL for the given sha1 hash. If the artifact is found, a
     * <code>MavenArtifact</code> is populated with the GAV.
     *
     * @param sha1 the SHA-1 hash string for which to search
     * @return the populated Maven GAV.
     * @throws IOException if it's unable to connect to the specified repository or if the specified artifact is not
     * found.
     */
    public List<MavenArtifact> searchSha1(String sha1) throws IOException {
        if (null == sha1 || !sha1.matches("^[0-9A-Fa-f]{40}$")) {
            throw new IllegalArgumentException("Invalid SHA1 format");
        }

        final URL url = new URL(rootURL + String.format("?q=1:\"%s\"&wt=xml", sha1));

        LOGGER.fine(String.format("Searching Central url %s", url.toString()));

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
                final DocumentBuilder builder = DocumentBuilderFactory
                        .newInstance().newDocumentBuilder();
                final Document doc = builder.parse(conn.getInputStream());
                final XPath xpath = XPathFactory.newInstance().newXPath();
                final String numFound = xpath.evaluate("/response/result/@numFound", doc);
                if ("0".equals(numFound)) {
                    missing = true;
                } else {
                    ArrayList<MavenArtifact> result = new ArrayList<MavenArtifact>();
                    NodeList docs = (NodeList) xpath.evaluate("/response/result/doc", doc, XPathConstants.NODESET);
                    for (int i = 0; i < docs.getLength(); i++) {
                        final String g = xpath.evaluate("./str[@name='g']", docs.item(i));
                        LOGGER.finest(String.format("GroupId: %s", g));
                        final String a = xpath.evaluate("./str[@name='a']", docs.item(i));
                        LOGGER.finest(String.format("ArtifactId: %s", a));
                        final String v = xpath.evaluate("./str[@name='v']", docs.item(i));
                        LOGGER.finest(String.format("Version: %s", v));
                        result.add(new MavenArtifact(g, a, v, url.toString()));
                    }

                    return result;
                }
            } catch (Throwable e) {
                // Anything else is jacked up XML stuff that we really can't recover
                // from well
                throw new IOException(e.getMessage(), e);
            }

            if (missing) {
                throw new FileNotFoundException("Artifact not found in Central");
            }
        } else {
            final String msg = String.format("Could not connect to Central received response code: %d %s",
                    conn.getResponseCode(), conn.getResponseMessage());
            LOGGER.fine(msg);
            throw new IOException(msg);
        }

        return null;
    }
}
