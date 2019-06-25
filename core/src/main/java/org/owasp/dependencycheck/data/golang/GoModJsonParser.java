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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.golang;

import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.NotThreadSafe;
import javax.json.*;
import javax.json.stream.JsonParsingException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses json output from `go mod edit -json`
 *
 * @author Matthijs van den Bos
 */
@NotThreadSafe
public class GoModJsonParser {

    /**
     * The JsonReader for parsing JSON
     */
    private final JsonReader jsonReader;

    /**
     * The List of ComposerDependencies found
     */
    private final List<GoModDependency> goModDependencies;

    /**
     * The LOGGER
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(GoModJsonParser.class);

    /**
     * Creates a ComposerLockParser from a JsonReader and an InputStream.
     *
     * @param inputStream the InputStream to parse
     */
    public GoModJsonParser(InputStream inputStream) {
        LOGGER.debug("Creating a ComposerLockParser");
        this.jsonReader = Json.createReader(inputStream);
        this.goModDependencies = new ArrayList<>();
    }

    /**
     * Process the input stream to create the list of dependencies.
     */
    public void process() throws AnalysisException {
        LOGGER.debug("Beginning go.mod processing");
        try {
            final JsonObject composer = jsonReader.readObject();
            if (composer.containsKey("Require")) {
                LOGGER.debug("Found modules");
                final JsonArray modules = composer.getJsonArray("Require");
                for (JsonObject module : modules.getValuesAs(JsonObject.class)) {
                    final String path = module.getString("Path");
                    String version = module.getString("Version");
                    if (version.startsWith("v")) {
                        version = version.substring(1);
                    }
                    goModDependencies.add(new GoModDependency(path, version));
                }
            }
        } catch (JsonParsingException jsonpe) {
            throw new AnalysisException("Error parsing stream", jsonpe);
        } catch (JsonException jsone) {
            throw new AnalysisException("Error reading stream", jsone);
        } catch (IllegalStateException ise) {
            throw new AnalysisException("Illegal state in go mod stream", ise);
        } catch (ClassCastException cce) {
            throw new AnalysisException("JSON not exactly matching output of `go mod edit -json`", cce);
        }
    }

    /**
     * Gets the list of dependencies.
     *
     * @return the list of dependencies
     */
    public List<GoModDependency> getDependencies() {
        return goModDependencies;
    }
}
