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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NexusSearchTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(NexusSearchTest.class);
    private NexusSearch searcher;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        String nexusUrl = getSettings().getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        LOGGER.debug(nexusUrl);
        searcher = new NexusSearch(getSettings(), false);
        Assume.assumeTrue(searcher.preflightRequest());
    }

    @Test(expected = IllegalArgumentException.class)
    @Ignore
    public void testNullSha1() throws Exception {
        searcher.searchSha1(null);
    }

    @Test(expected = IllegalArgumentException.class)
    @Ignore
    public void testMalformedSha1() throws Exception {
        searcher.searchSha1("invalid");
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test
    @Ignore
    public void testValidSha1() throws Exception {
        MavenArtifact ma = searcher.searchSha1("9977a8d04e75609cf01badc4eb6a9c7198c4c5ea");
        assertEquals("Incorrect group", "org.apache.maven.plugins", ma.getGroupId());
        assertEquals("Incorrect artifact", "maven-compiler-plugin", ma.getArtifactId());
        assertEquals("Incorrect version", "3.1", ma.getVersion());
        assertNotNull("URL Should not be null", ma.getArtifactUrl());
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test(expected = FileNotFoundException.class)
    @Ignore
    public void testMissingSha1() throws Exception {
        searcher.searchSha1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }
}
