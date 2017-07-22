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

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
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
 * Maven Plugin that checks project dependencies and the dependencies of all
 * child modules to see if they have any known published vulnerabilities.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "aggregate",
        defaultPhase = LifecyclePhase.VERIFY,
        aggregator = true,
        threadSafe = false,
        requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
        requiresOnline = true
)
public class AggregateMojo extends BaseDependencyCheckMojo {

    /**
     * The name of the report in the site.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "name", defaultValue = "dependency-check:aggregate", required = true)
    private String name = "dependency-check:aggregate";

    /**
     * Executes the aggregate dependency-check goal. This runs dependency-check
     * and generates the subsequent reports.
     *
     * @throws MojoExecutionException thrown if there is ane exception running
     * the Mojo
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build
     */
    @Override
    public void runCheck() throws MojoExecutionException, MojoFailureException {
        final Engine engine = loadEngine();
        if (engine == null) {
            return;
        }

        ExceptionCollection exCol = scanArtifacts(getProject(), engine);

        for (MavenProject childProject : getDescendants(this.getProject())) {
            final ExceptionCollection ex = scanArtifacts(childProject, engine);
            if (ex != null) {
                if (exCol == null) {
                    exCol = ex;
                }
                exCol.getExceptions().addAll(ex.getExceptions());
                if (ex.isFatal()) {
                    exCol.setFatal(true);
                    final String msg = String.format("Fatal exception(s) analyzing %s", childProject.getName());
                    if (this.isFailOnError()) {
                        throw new MojoExecutionException(msg, exCol);
                    }
                    getLog().error(msg);
                    if (getLog().isDebugEnabled()) {
                        getLog().debug(exCol);
                    }
                }
            }
        }

        try {
            engine.analyzeDependencies();
        } catch (ExceptionCollection ex) {
            if (exCol == null) {
                exCol = ex;
            } else if (ex.isFatal()) {
                exCol.setFatal(true);
                exCol.getExceptions().addAll(ex.getExceptions());
            }
            if (exCol.isFatal()) {
                final String msg = String.format("Fatal exception(s) analyzing %s", getProject().getName());
                if (this.isFailOnError()) {
                    throw new MojoExecutionException(msg, exCol);
                }
                getLog().error(msg);
                if (getLog().isDebugEnabled()) {
                    getLog().debug(exCol);
                }
                return;
            } else {
                final String msg = String.format("Exception(s) analyzing %s", getProject().getName());
                if (getLog().isDebugEnabled()) {
                    getLog().debug(msg, exCol);
                }
            }
        }
        File outputDir = getCorrectOutputDirectory(this.getProject());
        if (outputDir == null) {
            //in some regards we shouldn't be writing this, but we are anyway.
            //we shouldn't write this because nothing is configured to generate this report.
            outputDir = new File(this.getProject().getBuild().getDirectory());
        }
        try {
            final MavenProject p = this.getProject();
            engine.writeReports(p.getName(), p.getGroupId(), p.getArtifactId(), p.getVersion(), outputDir, getFormat());
        } catch (ReportException ex) {
            if (exCol == null) {
                exCol = new ExceptionCollection("Error writing aggregate report", ex);
            } else {
                exCol.addException(ex);
            }
            if (this.isFailOnError()) {
                throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
            } else {
                getLog().debug("One or more exceptions occurred during dependency-check analysis", exCol);
            }
        }
        showSummary(this.getProject(), engine.getDependencies());
        checkForFailure(engine.getDependencies());
        if (exCol != null && this.isFailOnError()) {
            throw new MojoExecutionException("One or more exceptions occurred during dependency-check analysis", exCol);
        }
        engine.cleanup();
        Settings.cleanup();
    }

    /**
     * Returns a set containing all the descendant projects of the given
     * project.
     *
     * @param project the project for which all descendants will be returned
     * @return the set of descendant projects
     */
    protected Set<MavenProject> getDescendants(MavenProject project) {
        if (project == null) {
            return Collections.emptySet();
        }
        final Set<MavenProject> descendants = new HashSet<>();
        int size;
        if (getLog().isDebugEnabled()) {
            getLog().debug(String.format("Collecting descendants of %s", project.getName()));
        }
        for (String m : project.getModules()) {
            for (MavenProject mod : getReactorProjects()) {
                try {
                    File mpp = new File(project.getBasedir(), m);
                    mpp = mpp.getCanonicalFile();
                    if (mpp.compareTo(mod.getBasedir()) == 0 && descendants.add(mod)
                            && getLog().isDebugEnabled()) {
                        getLog().debug(String.format("Descendant module %s added", mod.getName()));

                    }
                } catch (IOException ex) {
                    if (getLog().isDebugEnabled()) {
                        getLog().debug("Unable to determine module path", ex);
                    }
                }
            }
        }
        do {
            size = descendants.size();
            for (MavenProject p : getReactorProjects()) {
                if (project.equals(p.getParent()) || descendants.contains(p.getParent())) {
                    if (descendants.add(p) && getLog().isDebugEnabled()) {
                        getLog().debug(String.format("Descendant %s added", p.getName()));

                    }
                    for (MavenProject modTest : getReactorProjects()) {
                        if (p.getModules() != null && p.getModules().contains(modTest.getName())
                                && descendants.add(modTest)
                                && getLog().isDebugEnabled()) {
                            getLog().debug(String.format("Descendant %s added", modTest.getName()));
                        }
                    }
                }
                final Set<MavenProject> addedDescendants = new HashSet<>();
                for (MavenProject dec : descendants) {
                    for (String mod : dec.getModules()) {
                        try {
                            File mpp = new File(dec.getBasedir(), mod);
                            mpp = mpp.getCanonicalFile();
                            if (mpp.compareTo(p.getBasedir()) == 0) {
                                addedDescendants.add(p);
                            }
                        } catch (IOException ex) {
                            if (getLog().isDebugEnabled()) {
                                getLog().debug("Unable to determine module path", ex);
                            }
                        }
                    }
                }
                for (MavenProject addedDescendant : addedDescendants) {
                    if (descendants.add(addedDescendant) && getLog().isDebugEnabled()) {
                        getLog().debug(String.format("Descendant module %s added", addedDescendant.getName()));
                    }
                }
            }
        } while (size != 0 && size != descendants.size());
        if (getLog().isDebugEnabled()) {
            getLog().debug(String.format("%s has %d children", project, descendants.size()));
        }
        return descendants;
    }

    /**
     * Test if the project has pom packaging
     *
     * @param mavenProject Project to test
     * @return <code>true</code> if it has a pom packaging; otherwise
     * <code>false</code>
     */
    protected boolean isMultiModule(MavenProject mavenProject) {
        return "pom".equals(mavenProject.getPackaging());
    }

    /**
     * Initializes the engine.
     *
     * @return the Engine used to execute dependency-check
     * @throws MojoExecutionException thrown if there is an exception running
     * the Mojo
     * @throws MojoFailureException thrown if dependency-check is configured to
     * fail the build if severe CVEs are identified.
     */
    protected Engine loadEngine() throws MojoExecutionException, MojoFailureException {
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
            getLog().error(msg, ex);
        }
        return engine;
    }

    @Override
    public boolean canGenerateReport() {
        return true; //aggregate always returns true for now - we can look at a more complicated/accurate solution later
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
        return "Generates an aggregate report of all child Maven projects providing details on any "
                + "published vulnerabilities within project dependencies. This report is a best "
                + "effort and may contain false positives and false negatives.";
    }
}
