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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.util.List;
import java.util.logging.Logger;
import org.apache.maven.project.MavenProject;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.CPEAnalyzer;
import org.owasp.dependencycheck.analyzer.FileTypeAnalyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * A modified version of the core engine specifically designed to persist some data between multiple executions of a
 * multi-module Maven project.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class Engine extends org.owasp.dependencycheck.Engine {

    /**
     * The logger.
     */
    private static final transient Logger LOGGER = Logger.getLogger(Engine.class.getName());
    /**
     * A key used to persist an object in the MavenProject.
     */
    private static final String CPE_ANALYZER_KEY = "dependency-check-CPEAnalyzer";
    /**
     * The current MavenProject.
     */
    private MavenProject currentProject;
    /**
     * The list of MavenProjects that are part of the current build.
     */
    private List<MavenProject> reactorProjects;
    /**
     * Key used in the MavenProject context values to note whether or not an update has been executed.
     */
    public static final String UPDATE_EXECUTED_FLAG = "dependency-check-update-executed";

    /**
     * Creates a new Engine to perform anyalsis on dependencies.
     *
     * @param project the current Maven project
     * @param reactorProjects the reactor projects for the current Maven execution
     * @throws DatabaseException thrown if there is an issue connecting to the database
     */
    public Engine(MavenProject project, List<MavenProject> reactorProjects) throws DatabaseException {
        this.currentProject = project;
        this.reactorProjects = reactorProjects;
        final MavenProject root = getExecutionRoot();
        if (root != null) {
            LOGGER.fine(String.format("Checking root project, %s, if updates have already been completed", root.getArtifactId()));
        } else {
            LOGGER.fine("Checking root project, null, if updates have already been completed");
        }
        if (root != null && root.getContextValue(UPDATE_EXECUTED_FLAG) != null) {
            System.setProperty(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE.toString());
        }
        initializeEngine();
        if (root != null) {
            root.setContextValue(UPDATE_EXECUTED_FLAG, Boolean.TRUE);
        }
    }

    /**
     * This constructor should not be called. Use Engine(MavenProject) instead.
     *
     * @throws DatabaseException thrown if there is an issue connecting to the database
     */
    private Engine() throws DatabaseException {
    }

    /**
     * Initializes the given analyzer. This skips the initialization of the CPEAnalyzer if it has been initialized by a
     * previous execution.
     *
     * @param analyzer the analyzer to initialize
     * @return the initialized analyzer
     */
    @Override
    protected Analyzer initializeAnalyzer(Analyzer analyzer) {
        if ((analyzer instanceof CPEAnalyzer)) {
            CPEAnalyzer cpe = getPreviouslyLoadedCPEAnalyzer();
            if (cpe != null) {
                return cpe;
            }
            cpe = (CPEAnalyzer) super.initializeAnalyzer(analyzer);
            storeCPEAnalyzer(cpe);
        }
        return super.initializeAnalyzer(analyzer);
    }

    /**
     * Releases resources used by the analyzers by calling close() on each analyzer.
     */
    @Override
    public void cleanup() {
        super.cleanup();
        if (currentProject == null || reactorProjects == null) {
            return;
        }
        if (this.currentProject == reactorProjects.get(reactorProjects.size() - 1)) {
            final CPEAnalyzer cpe = getPreviouslyLoadedCPEAnalyzer();
            if (cpe != null) {
                cpe.close();
            }
        }
    }

    /**
     * Closes the given analyzer. This skips closing the CPEAnalyzer.
     *
     * @param analyzer the analyzer to close
     */
    @Override
    protected void closeAnalyzer(Analyzer analyzer) {
        if ((analyzer instanceof CPEAnalyzer)) {
            if (getPreviouslyLoadedCPEAnalyzer() == null) {
                super.closeAnalyzer(analyzer);
            }
        } else {
            super.closeAnalyzer(analyzer);
        }
    }

    /**
     * Gets the CPEAnalyzer from the root Maven Project.
     *
     * @return an initialized CPEAnalyzer
     */
    private CPEAnalyzer getPreviouslyLoadedCPEAnalyzer() {
        CPEAnalyzer cpe = null;
        final MavenProject project = getExecutionRoot();
        if (project != null) {
            final Object obj = project.getContextValue(CPE_ANALYZER_KEY);
            if (obj != null && obj instanceof CPEAnalyzer) {
                cpe = (CPEAnalyzer) project.getContextValue(CPE_ANALYZER_KEY);
            }
        }
        return cpe;
    }

    /**
     * Stores a CPEAnalyzer in the root Maven Project.
     *
     * @param cpe the CPEAnalyzer to store
     */
    private void storeCPEAnalyzer(CPEAnalyzer cpe) {
        final MavenProject p = getExecutionRoot();
        if (p != null) {
            p.setContextValue(CPE_ANALYZER_KEY, cpe);
        }
    }

    /**
     * Returns the root Maven Project.
     *
     * @return the root Maven Project
     */
    private MavenProject getExecutionRoot() {
        if (reactorProjects == null) {
            return null;
        }
        for (MavenProject p : reactorProjects) {
            if (p.isExecutionRoot()) {
                return p;
            }
        }
        //the following should  never run, but leaving it as a failsafe.
        if (this.currentProject == null) {
            return null;
        }
        MavenProject p = this.currentProject;
        while (p.getParent() != null) {
            p = p.getParent();
        }
        return p;
    }

    public void resetFileTypeAnalyzers() {
        for (FileTypeAnalyzer a : getFileTypeAnalyzers()) {
            a.reset();
        }
    }
}
