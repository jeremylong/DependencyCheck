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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileNotFoundException;
import java.net.URL;
import java.util.logging.Logger;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.utils.Settings;

public class NexusSearchTest {

    private static final Logger LOGGER = Logger.getLogger(NexusSearchTest.class.getName());
    private NexusSearch searcher;

    @Before
    public void setUp() throws Exception {
        String nexusUrl = Settings.getString(Settings.KEYS.ANALYZER_NEXUS_URL);
        LOGGER.fine(nexusUrl);
        searcher = new NexusSearch(new URL(nexusUrl));
        Assume.assumeTrue(searcher.preflightRequest());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullSha1() throws Exception {
        searcher.searchSha1(null);
    }

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
        assertNotNull("URL Should not be null", ma.getArtifactUrl());
    }

    // This test does generate network traffic and communicates with a host
    // you may not be able to reach. Remove the @Ignore annotation if you want to
    // test it anyway
    @Test(expected = FileNotFoundException.class)
    public void testMissingSha1() throws Exception {
        searcher.searchSha1("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }
}

// vim: cc=120:sw=4:ts=4:sts=4
