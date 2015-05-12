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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.owasp.dependencycheck.analyzer.DependencyBundlingAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Maven Plugin that checks project dependencies and the dependencies of all child modules to see if they have any known published
 * vulnerabilities.
 *
 * @author Jeremy Long
 */
@Mojo(
        name = "aggregate",
        defaultPhase = LifecyclePhase.SITE,
        aggregator = true,
        threadSafe = true,
        requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
        requiresOnline = true
)
public class AggregateMojo extends BaseDependencyCheckMojo {

    /**
     * Logger field reference.
     */
    private static final Logger LOGGER = Logger.getLogger(AggregateMojo.class.getName());

    /**
     * Executes the aggregate dependency-check goal. This runs dependency-check and generates the subsequent reports.
     *
     * @throws MojoExecutionException thrown if there is ane exception running the mojo
     * @throws MojoFailureException thrown if dependency-check is configured to fail the build
     */
    @Override
    public void runCheck() throws MojoExecutionException, MojoFailureException {
        final Engine engine = generateDataFile();

        if (getProject() == getReactorProjects().get(getReactorProjects().size() - 1)) {

            //ensure that the .ser file was created for each.
            for (MavenProject current : getReactorProjects()) {
                final File dataFile = getDataFile(current);
                if (dataFile == null) { //dc was never run on this project. write the ser to the target.
                    LOGGER.fine(String.format("Executing dependency-check on %s", current.getName()));
                    generateDataFile(engine, current);
                }
            }

            for (MavenProject current : getReactorProjects()) {
                List<Dependency> dependencies = readDataFile(current);
                if (dependencies == null) {
                    dependencies = new ArrayList<Dependency>();
                }
                final Set<MavenProject> childProjects = getDescendants(current);
                for (MavenProject reportOn : childProjects) {
                    final List<Dependency> childDeps = readDataFile(reportOn);
                    if (childDeps != null && !childDeps.isEmpty()) {
                        LOGGER.fine(String.format("Adding %d dependencies from %s", childDeps.size(), reportOn.getName()));
                        dependencies.addAll(childDeps);
                    } else {
                        LOGGER.fine(String.format("No dependencies read for %s", reportOn.getName()));
                    }
                }
                engine.getDependencies().clear();
                engine.getDependencies().addAll(dependencies);
                final DependencyBundlingAnalyzer bundler = new DependencyBundlingAnalyzer();
                try {
                    LOGGER.fine(String.format("Dependency count pre-bundler: %s", engine.getDependencies().size()));
                    bundler.analyze(null, engine);
                    LOGGER.fine(String.format("Dependency count post-bundler: %s", engine.getDependencies().size()));
                } catch (AnalysisException ex) {
                    LOGGER.log(Level.WARNING, "An error occured grouping the dependencies; duplicate entries may exist in the report", ex);
                    LOGGER.log(Level.FINE, "Bundling Exception", ex);
                }

                File outputDir = getCorrectOutputDirectory(current);
                if (outputDir == null) {
                    //in some regards we shouldn't be writting this, but we are anyway.
                    //we shouldn't write this because nothing is configured to generate this report.
                    outputDir = new File(current.getBuild().getDirectory());
                }
                writeReports(engine, current, outputDir);
            }
        }
        engine.cleanup();
        Settings.cleanup();
    }

    /**
     * Returns a set containing all the descendant projects of the given project.
     *
     * @param project the project for which all descendants will be returned
     * @return the set of descendant projects
     */
    protected Set<MavenProject> getDescendants(MavenProject project) {
        if (project == null) {
            return Collections.emptySet();
        }
        final Set<MavenProject> descendants = new HashSet<MavenProject>();
        int size = 0;
        LOGGER.fine(String.format("Collecting descendants of %s", project.getName()));
        for (String m : project.getModules()) {
            for (MavenProject mod : getReactorProjects()) {
                try {
                    File mpp = new File(project.getBasedir(), m);
                    mpp = mpp.getCanonicalFile();
                    if (mpp.compareTo(mod.getBasedir()) == 0 && descendants.add(mod)) {
                        LOGGER.fine(String.format("Decendent module %s added", mod.getName()));
                    }
                } catch (IOException ex) {
                    LOGGER.log(Level.FINE, "Unable to determine module path", ex);
                }
            }
        }
        do {
            size = descendants.size();
            for (MavenProject p : getReactorProjects()) {
                if (project.equals(p.getParent()) || descendants.contains(p.getParent())) {
                    if (descendants.add(p)) {
                        LOGGER.fine(String.format("Decendent %s added", p.getName()));
                    }
                    for (MavenProject modTest : getReactorProjects()) {
                        if (p.getModules() != null && p.getModules().contains(modTest.getName())
                                && descendants.add(modTest)) {
                            LOGGER.fine(String.format("Decendent %s added", modTest.getName()));
                        }
                    }
                }
                for (MavenProject dec : descendants) {
                    for (String mod : dec.getModules()) {
                        try {
                            File mpp = new File(dec.getBasedir(), mod);
                            mpp = mpp.getCanonicalFile();
                            if (mpp.compareTo(p.getBasedir()) == 0 && descendants.add(p)) {
                                LOGGER.fine(String.format("Decendent module %s added", p.getName()));
                            }
                        } catch (IOException ex) {
                            LOGGER.log(Level.FINE, "Unable to determine module path", ex);
                        }
                    }
                }
            }
        } while (size != 0 && size != descendants.size());
        LOGGER.fine(String.format("%s has %d children", project, descendants.size()));
        return descendants;
    }

    /**
     * Test if the project has pom packaging
     *
     * @param mavenProject Project to test
     * @return <code>true</code> if it has a pom packaging; otherwise <code>false</code>
     */
    protected boolean isMultiModule(MavenProject mavenProject) {
        return "pom".equals(mavenProject.getPackaging());
    }

    /**
     * Initilizes the engine, runs a scan, and writes the serialized dependencies to disk.
     *
     * @return the Engine used to execute dependency-check
     * @throws MojoExecutionException thrown if there is an exception running the mojo
     * @throws MojoFailureException thrown if dependency-check is configured to fail the build if severe CVEs are identified.
     */
    protected Engine generateDataFile() throws MojoExecutionException, MojoFailureException {
        final Engine engine;
        try {
            engine = initializeEngine();
        } catch (DatabaseException ex) {
            LOGGER.log(Level.FINE, "Database connection error", ex);
            throw new MojoExecutionException("An exception occured connecting to the local database. Please see the log file for more details.", ex);
        }
        return generateDataFile(engine, getProject());
    }

    /**
     * Runs dependency-check's Engine and writes the serialized dependencies to disk.
     *
     * @param engine the Engine to use when scanning.
     * @param project the project to scan and generate the data file for
     * @return the Engine used to execute dependency-check
     * @throws MojoExecutionException thrown if there is an exception running the mojo
     * @throws MojoFailureException thrown if dependency-check is configured to fail the build if severe CVEs are identified.
     */
    protected Engine generateDataFile(Engine engine, MavenProject project) throws MojoExecutionException, MojoFailureException {
        LOGGER.fine(String.format("Begin Scanning: %s", project.getName()));
        engine.getDependencies().clear();
        engine.resetFileTypeAnalyzers();
        scanArtifacts(project, engine);
        engine.analyzeDependencies();
        final File target = new File(project.getBuild().getDirectory());
        writeDataFile(project, target, engine.getDependencies());
        showSummary(project, engine.getDependencies());
        checkForFailure(engine.getDependencies());
        return engine;
    }

    @Override
    public boolean canGenerateReport() {
        return true; //aggregate always returns true for now - we can look at a more complicated/acurate solution later
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    public String getName(Locale locale) {
        return "dependency-check:aggregate";
    }

    /**
     * Gets the description of the Dependency-Check report to be displayed in the Maven Generated Reports page.
     *
     * @param locale The Locale to get the description for
     * @return the description
     */
    public String getDescription(Locale locale) {
        return "Generates an aggregate report of all child Maven projects providing details on any "
                + "published vulnerabilities within project dependencies. This report is a best "
                + "effort and may contain false positives and false negatives.";
    }
}
