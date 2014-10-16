package org.owasp.dependencycheck.data.solr;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.utils.Settings;

import java.io.FileNotFoundException;
import java.net.URL;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by colezlaw on 10/13/14.
 */
public class SolrSearchTest extends BaseTest {
    private static final Logger LOGGER = Logger.getLogger(SolrSearchTest.class.getName());
    private SolrSearch searcher;

    @Before
    public void setUp() throws Exception {
        String solrUrl = Settings.getString(Settings.KEYS.ANALYZER_SOLR_URL);
        LOGGER.fine(solrUrl);
        searcher = new SolrSearch(new URL(solrUrl));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullSha1() throws Exception { searcher.searchSha1(null); }

    @Test(expected = IllegalArgumentException.class)
    public void testMalformedSha1() throws Exception {
        searcher.searchSha1("invalid");
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test
    public void testValidSha1() throws Exception {
        MavenArtifact ma = searcher.searchSha1("9977a8d04e75609cf01badc4eb6a9c7198c4c5ea");
        assertEquals("Incorrect group", "org.apache.maven.plugins", ma.getGroupId());
        assertEquals("Incorrect artifact", "maven-compiler-plugin", ma.getArtifactId());
        assertEquals("Incorrect version", "3.1", ma.getVersion());
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test(expected = FileNotFoundException.class)
    public void testMissingSha1() throws Exception {
        searcher.searchSha1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }
}
