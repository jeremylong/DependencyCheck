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
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import java.io.InputStream;
import java.util.List;
import static org.junit.Assume.assumeFalse;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;

public class NspSearchTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(NspSearchTest.class);
    private NspSearch searcher;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        searcher = new NspSearch(getSettings());
    }

    @Test
    public void testNspSearchPositive() throws Exception {
        InputStream in = BaseTest.getResourceAsStream(this, "nsp/package.json");
        try (JsonReader jsonReader = Json.createReader(in)) {
            final JsonObject packageJson = jsonReader.readObject();
            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);
            final JsonObjectBuilder builder = Json.createObjectBuilder();
            final JsonObject nspPayload = builder.add("package", sanitizedJson).build();
            final List<Advisory> advisories = searcher.submitPackage(nspPayload);
            Assert.assertTrue(advisories.size() > 0);
        } catch (Exception ex) {
            assumeFalse(ex instanceof URLConnectionFailureException
                    && ex.getMessage().contains("Unable to connect to "));
            throw ex;
        }
    }

    @Test(expected = AnalysisException.class)
    public void testNspSearchNegative() throws Exception {
        InputStream in = BaseTest.getResourceAsStream(this, "nsp/package.json");
        try (JsonReader jsonReader = Json.createReader(in)) {
            final JsonObject packageJson = jsonReader.readObject();
            final JsonObject sanitizedJson = SanitizePackage.sanitize(packageJson);
            searcher.submitPackage(sanitizedJson);
        } catch (Exception ex) {
            assumeFalse(ex instanceof URLConnectionFailureException
                    && ex.getMessage().contains("Unable to connect to "));
            throw ex;
        }
    }

}
