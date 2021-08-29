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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.processing;

import java.io.InputStream;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.golang.GoModJsonParser;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.processing.Processor;

/**
 * Processor for the output of `go list -m -json all`.
 *
 * @author Jeremy Long
 */
public class GoModProcessor extends Processor<InputStream> {

    /**
     * Reference to the dependency-check engine.
     */
    private final Engine engine;
    /**
     * Reference to the go.mod dependency.
     */
    private final Dependency goDependency;
    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private AnalysisException analysisException;

    /**
     * Constructs a new processor to consume the output of `go list -m -json
     * all`.
     *
     * @param goDependency a reference to `go.mod` dependency
     * @param engine a reference to the dependency-check engine
     */
    public GoModProcessor(Dependency goDependency, Engine engine) {
        this.engine = engine;
        this.goDependency = goDependency;
    }

    @Override
    public void run() {
        try {
            GoModJsonParser.process(getInput()).forEach(goDep
                    -> engine.addDependency(goDep.toDependency(goDependency))
            );
        } catch (AnalysisException ex) {
            analysisException = new AnalysisException("Error analyzing '" + goDependency.getFilePath()
                    + "'; " + ex.getMessage(), ex.getCause());
        }
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws AnalysisException thrown if an AnalysisException occurred
     */
    @Override
    public void close() throws AnalysisException {
        if (analysisException != null) {
            throw analysisException;
        }
    }

}
