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
package org.owasp.dependencycheck.data.nodeaudit;

import org.junit.Assert;
import org.junit.Test;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class SanitizePackageTest {

    @Test
    public void testSanitizer() {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("name", "my app")
                .add("version", "1.0.0")
                .add("random", "random")
                .add("lockfileVersion", 1)
                .add("requires", true)
                .add("dependencies",
                        Json.createObjectBuilder().add("abbrev",
                                Json.createObjectBuilder()
                                        .add("version", "1.1.1")
                                        .add("resolved", "https://registry.npmjs.org/abbrev/-/abbrev-1.1.1.tgz")
                                        .add("integrity", "sha512-nne9/IiQ/hzIhY6pdDnbBtz7DjPTKrY00P/zvPSm5pOFkl6xuGrGnXn/VtTNNfNtAfZ9/1RtehkszU9qcTii0Q==")
                                        .add("dev", true)
                        )

                );

        JsonObject packageJson = builder.build();
        JsonObject sanitized = SanitizePackage.sanitize(packageJson);

        Assert.assertTrue(sanitized.containsKey("name"));
        Assert.assertTrue(sanitized.containsKey("version"));
        Assert.assertTrue(sanitized.containsKey("dependencies"));
        Assert.assertTrue(sanitized.containsKey("requires"));

        JsonObject requires = sanitized.getJsonObject("requires");
        Assert.assertTrue(requires.containsKey("abbrev"));
        Assert.assertEquals("1.1.1", requires.getString("abbrev"));

        Assert.assertFalse(sanitized.containsKey("lockfileVersion"));
        Assert.assertFalse(sanitized.containsKey("random"));
    }
}
