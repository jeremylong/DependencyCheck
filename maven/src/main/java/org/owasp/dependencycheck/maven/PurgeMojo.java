/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.util.Locale;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.exception.ExceptionCollection;

/**
 * Maven Plugin that purges the local copy of the NVD data.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "purge",
        defaultPhase = LifecyclePhase.GENERATE_RESOURCES,
        requiresProject = false,
        threadSafe = true,
        requiresDependencyResolution = ResolutionScope.NONE,
        requiresOnline = true,
        aggregator = true
)
public class PurgeMojo extends BaseDependencyCheckMojo {

    /**
     * Returns false; this mojo cannot generate a report.
     *
     * @return <code>false</code>
     */
    @Override
    public boolean canGenerateReport() {
        return false;
    }

    /**
     * Purges the local copy of the NVD.
     *
     * @throws MojoExecutionException thrown if there is an exception executing
     * the goal
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build
     */
    @Override
    protected void runCheck() throws MojoExecutionException, MojoFailureException {
        populateSettings();
        try (Engine engine = new Engine(Engine.Mode.EVIDENCE_PROCESSING, getSettings())) {
            engine.purge();
        } finally {
            getSettings().cleanup();
        }
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    @Override
    public String getName(Locale locale) {
        return "dependency-check-purge";
    }

    /**
     * Gets the description of the Dependency-Check report to be displayed in
     * the Maven Generated Reports page.
     *
     * @param locale The Locale to get the description for
     * @return the description
     */
    @Override
    public String getDescription(Locale locale) {
        return "Purges the local cache of the NVD dataT.";
    }

    /**
     * Throws an exception if called. The purge mojo does not scan dependencies.
     *
     * @param engine the engine used to scan
     * @return a collection of exceptions
     * @throws MojoExecutionException thrown if there is an exception
     */
    @Override
    protected ExceptionCollection scanDependencies(Engine engine) throws MojoExecutionException {
        throw new UnsupportedOperationException("Operation not supported");
    }
}
