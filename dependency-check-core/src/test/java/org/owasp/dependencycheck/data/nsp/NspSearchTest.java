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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

public class NspSearchTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(NspSearchTest.class);
    private NspSearch searcher;

    @Before
    public void setUp() throws Exception {
        String url = Settings.getString(Settings.KEYS.ANALYZER_NSP_URL);
        LOGGER.debug(url);
        searcher = new NspSearch(new URL(url));
    }

    //@Test
    //todo: this test does not work in Java 7 - UNABLE TO FIND VALID CERTIFICATION PATH TO REQUESTED TARGET
    public void testNspSearchPositive() throws Exception {
        InputStream in = BaseTest.getResourceAsStream(this, "nsp/package.json");
        try (JsonReader jsonReader = Json.createReader(in)) {
            final JsonObject packageJson = jsonReader.readObject();
            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);
            final JsonObjectBuilder builder = Json.createObjectBuilder();
            final JsonObject nspPayload = builder.add("package", sanitizedJson).build();
            final List<Advisory> advisories = searcher.submitPackage(nspPayload);
            Assert.assertTrue(advisories.size() > 0);
        }
    }

    //@Test(expected = IOException.class)
    //todo: this test does not work in Java 7 - UNABLE TO FIND VALID CERTIFICATION PATH TO REQUESTED TARGET
    public void testNspSearchNegative() throws Exception {
        InputStream in = BaseTest.getResourceAsStream(this, "nsp/package.json");
        try (JsonReader jsonReader = Json.createReader(in)) {
            final JsonObject packageJson = jsonReader.readObject();
            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);
            searcher.submitPackage(sanitizedJson);
        }
    }

}
