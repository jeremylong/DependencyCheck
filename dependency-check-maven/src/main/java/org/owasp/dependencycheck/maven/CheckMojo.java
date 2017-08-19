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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.util.Locale;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Maven Plugin that checks the project dependencies to see if they have any
 * known published vulnerabilities.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "check",
        defaultPhase = LifecyclePhase.VERIFY,
        threadSafe = false,
        requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
        requiresOnline = true
)
public class CheckMojo extends BaseDependencyCheckMojo {

    /**
     * The name of the report in the site.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "name", defaultValue = "dependency-check", required = true)
    private String name = "dependency-check";

    /**
     * Returns whether or not a the report can be generated.
     *
     * @return <code>true</code> if the report can be generated; otherwise
     * <code>false</code>
     */
    @Override
    public boolean canGenerateReport() {
        populateSettings();
        boolean isCapable = false;
        for (Artifact a : getProject().getArtifacts()) {
            if (!getArtifactScopeExcluded().passes(a.getScope())) {
                isCapable = true;
                break;
            }
        }
        return isCapable;
    }

    /**
     * Executes the dependency-check engine on the project's dependencies and
     * generates the report.
     *
     * @throws MojoExecutionException thrown if there is an exception executing
     * the goal
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build
     */
    @Override
    public void runCheck() throws MojoExecutionException, MojoFailureException {
        Engine engine = null;
        try {
            engine = initializeEngine();
        } catch (DatabaseException ex) {
            if (getLog().isDebugEnabled()) {
                getLog().debug("Database connection error", ex);
            }
            final String msg = "An exception occurred connecting to the local database. Please see the log file for more details.";
            if (this.isFailOnError()) {
                throw new MojoExecutionException(msg, ex);
            }
            getLog().error(msg);
        }
        if (engine != null) {
            ExceptionCollection exCol = scanArtifacts(getProject(), engine);
            if (engine.getDependencies().isEmpty()) {
                getLog().info("No dependencies were identified that could be analyzed by dependency-check");
            }
            try {
                engine.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                if (this.isFailOnError() && ex.isFatal()) {
                    throw new MojoExecutionException("One or more exceptions occurred during analysis", ex);
                }
                exCol = ex;
            }
            if (exCol == null || !exCol.isFatal()) {
                try {
                    final MavenProject p = this.getProject();
                    engine.writeReports(p.getName(), p.getGroupId(), p.getArtifactId(), p.getVersion(), getCorrectOutputDirectory(), getFormat());
                } catch (ReportException ex) {
                    if (this.isFailOnError()) {
                        if (exCol != null) {
                            exCol.addException(ex);
                        } else {
                            exCol = new ExceptionCollection("Unable to write the dependency-check report", ex);
                        }
                    }
                }
                showSummary(getProject(), engine.getDependencies());
                checkForFailure(engine.getDependencies());
                if (exCol != null && this.isFailOnError()) {
                    throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
                }
            }
            engine.cleanup();
        }
        Settings.cleanup();
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    @Override
    public String getName(Locale locale) {
        return name;
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
        return "Generates a report providing details on any published vulnerabilities within project dependencies. "
                + "This report is a best effort and may contain false positives and false negatives.";
    }

}
