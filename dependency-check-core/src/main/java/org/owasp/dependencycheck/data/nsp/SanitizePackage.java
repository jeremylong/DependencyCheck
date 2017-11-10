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

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Class used to create a Sanitized version of package.json suitable for
 * submission to the nsp/check service.
 *
 * @author Steve Springett
 */
@ThreadSafe
public final class SanitizePackage {

    /**
     * Private constructor for utility class.
     */
    private SanitizePackage() {
        //empty
    }
    /**
     * Specifies a whitelist of allowable objects that package.json should
     * contain.
     */
    private static final List<String> WHITELIST = new ArrayList<>(Arrays.asList(
            "name",
            "version",
            "engine",
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
            "bundleDependencies",
            "bundledDependencies"
    ));

    /**
     * The NSP API only accepts a subset of objects typically found in
     * package.json. This method accepts a JsonObject of a raw package.json file
     * and returns a new 'sanitized' version based on a pre-defined whitelist of
     * allowable object NSP accepts.
     *
     * @param rawPackage a raw package.json file
     * @return a sanitized version of the package.json file
     */
    public static JsonObject sanitize(JsonObject rawPackage) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        if (rawPackage.get("name") == null) {
            // Reproduce the behavior of 'nsp check' by not failing on a
            // package.json without a name field (string).
            // https://github.com/jeremylong/DependencyCheck/issues/975
            builder.add("name", "1");
        }
        for (Map.Entry<String, JsonValue> entry : rawPackage.entrySet()) {
            if (WHITELIST.contains(entry.getKey())) {
                builder.add(entry.getKey(), entry.getValue());
            }
        }
        return builder.build();
    }

}
