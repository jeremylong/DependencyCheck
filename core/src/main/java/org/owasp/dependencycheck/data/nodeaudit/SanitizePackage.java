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

import java.util.Map.Entry;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Class used to create a Sanitized version of package-lock.json suitable for
 * submission to the NPM Audit API service.
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
     * The NPM Audit API only accepts a modified version of package-lock.json.
     * This method will make the necessary modifications in-memory, sanitizing
     * non-public dependencies by omitting them, and returns a new 'sanitized'
     * version.
     *
     * @param packageJson a raw package-lock.json file
     * @return a modified/sanitized version of the package-lock.json file
     */
    public static JsonObject sanitize(JsonObject packageJson) {
        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        final String projectName = packageJson.getString("name", "");
        final String projectVersion = packageJson.getString("version", "");
        if (!projectName.isEmpty()) {
            payloadBuilder.add("name", projectName);
        }
        if (!projectVersion.isEmpty()) {
            payloadBuilder.add("version", projectVersion);
        }

        // In most package-lock.json files, 'requires' is a boolean, however, NPM Audit expects
        // 'requires' to be an object containing key/value pairs corresponding to the module
        // name (key) and version (value).
        final JsonValue jsonValue = packageJson.get("requires");
        if (jsonValue==null || jsonValue.getValueType() != JsonValue.ValueType.OBJECT) {
            final JsonObjectBuilder requiresBuilder = Json.createObjectBuilder();
            final JsonObject dependencies = packageJson.getJsonObject("dependencies");
            for (Entry<String,JsonValue> entry: dependencies.entrySet()) {
                //final JsonObject module = dependencies.getJsonObject(moduleName);
                final String version;
                if (entry.getValue().getValueType() == JsonValue.ValueType.OBJECT) {
                    version = ((JsonObject) entry.getValue()).getString("version");
                } else  {
                    final String tmp = entry.getValue().toString();
                    if (tmp.startsWith("\"")) {
                        version = tmp.substring(1, tmp.length()-1);
                    } else {
                        version = tmp;
                    }
                }
                requiresBuilder.add(entry.getKey(), version);
            }
            payloadBuilder.add("requires", requiresBuilder.build());
        }

        payloadBuilder.add("dependencies", packageJson.getJsonObject("dependencies"));
        payloadBuilder.add("install", Json.createArrayBuilder().build());
        payloadBuilder.add("remove", Json.createArrayBuilder().build());
        payloadBuilder.add("metadata", Json.createObjectBuilder()
                .add("npm_version", "6.1.0")
                .add("node_version", "v10.5.0")
                .add("platform", "linux")
        );

        // Create a new 'package-lock.json' object
        return payloadBuilder.build();
    }

}
