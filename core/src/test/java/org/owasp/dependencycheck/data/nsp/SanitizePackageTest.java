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
import org.junit.Test;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class SanitizePackageTest {

    @Test
    public void testSanitizer() throws Exception {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder
                .add("name", "my app")
                .add("version", "1.0.0")
                .add("description", "my app does amazing things")
                .add("keywords", "best, app, ever")
                .add("homepage", "http://example.com")
                .add("bugs", "http://example.com/bugs")
                .add("license", "Apache-2.0")
                .add("main", "myscript")
                .add("dependencies", "{ \"foo\" : \"1.0.0 - 2.9999.9999\"}")
                .add("devDependencies", "{ \"foo\" : \"1.0.0 - 2.9999.9999\"}")
                .add("peerDependencies", "{ \"foo\" : \"1.0.0 - 2.9999.9999\"}")
                .add("bundledDependencies", "{ \"foo\" : \"1.0.0 - 2.9999.9999\"}")
                .add("optionalDependencies", "{ \"foo\" : \"1.0.0 - 2.9999.9999\"}");

        JsonObject packageJson = builder.build();
        JsonObject sanitized = SanitizePackage.sanitize(packageJson);

        Assert.assertTrue(sanitized.containsKey("name"));
        Assert.assertTrue(sanitized.containsKey("version"));
        Assert.assertTrue(sanitized.containsKey("dependencies"));
        Assert.assertTrue(sanitized.containsKey("devDependencies"));
        Assert.assertTrue(sanitized.containsKey("peerDependencies"));
        Assert.assertTrue(sanitized.containsKey("bundledDependencies"));
        Assert.assertTrue(sanitized.containsKey("optionalDependencies"));

        Assert.assertFalse(sanitized.containsKey("description"));
        Assert.assertFalse(sanitized.containsKey("keywords"));
        Assert.assertFalse(sanitized.containsKey("homepage"));
        Assert.assertFalse(sanitized.containsKey("bugs"));
        Assert.assertFalse(sanitized.containsKey("license"));
        Assert.assertFalse(sanitized.containsKey("main"));
    }
}
