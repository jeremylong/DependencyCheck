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

import java.util.logging.Logger;
import org.apache.maven.project.MavenProject;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.analyzer.CPEAnalyzer;
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
     * Creates a new Engine to perform anyalsis on dependencies.
     *
     * @param project the current Maven project
     * @throws DatabaseException thrown if there is an issue connecting to the database
     */
    public Engine(MavenProject project) throws DatabaseException {
        this.currentProject = project;
        MavenProject parent = getRootParent();
        if (parent != null && parent.getContextValue("dependency-check-data-was-updated") != null) {
            System.setProperty(Settings.KEYS.AUTO_UPDATE, Boolean.FALSE.toString());
        }
        initializeEngine();
        if (parent != null) {
            parent.setContextValue("dependency-check-data-was-updated", Boolean.valueOf(true));
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
            CPEAnalyzer cpe = getPreviouslyLoadedAnalyzer();
            if (cpe != null) {
                return cpe;
            }
            cpe = (CPEAnalyzer) super.initializeAnalyzer(analyzer);
            storeCPEAnalyzer(cpe);
        }
        return super.initializeAnalyzer(analyzer);
    }

    /**
     * Closes the given analyzer. This skips closing the CPEAnalyzer.
     *
     * @param analyzer
     */
    @Override
    protected void closeAnalyzer(Analyzer analyzer) {
        if ((analyzer instanceof CPEAnalyzer)) {
            if (getPreviouslyLoadedAnalyzer() == null) {
                super.closeAnalyzer(analyzer);
            }
        } else {
            super.closeAnalyzer(analyzer);
        }
    }

    /**
     * Closes the CPEAnalyzer if it has been created and persisted in the root parent MavenProject context.
     */
    public void cleanupFinal() {
        CPEAnalyzer cpe = getPreviouslyLoadedAnalyzer();
        if (cpe != null) {
            cpe.close();
        }
    }

    /**
     * Gets the CPEAnalyzer from the root Maven Project.
     *
     * @return an initialized CPEAnalyzer
     */
    private CPEAnalyzer getPreviouslyLoadedAnalyzer() {
        CPEAnalyzer cpe = null;
        MavenProject project = getRootParent();
        if (project != null) {
            cpe = (CPEAnalyzer) project.getContextValue(CPE_ANALYZER_KEY);
        }
        return cpe;
    }

    /**
     * Stores a CPEAnalyzer in the root Maven Project.
     *
     * @param cpe the CPEAnalyzer to store
     */
    private void storeCPEAnalyzer(CPEAnalyzer cpe) {
        MavenProject p = getRootParent();
        if (p != null) {
            p.setContextValue(CPE_ANALYZER_KEY, cpe);
        }
    }

    /**
     * Returns the root Maven Project.
     *
     * @return the root Maven Project
     */
    private MavenProject getRootParent() {
        if (this.currentProject == null) {
            return null;
        }
        MavenProject p = this.currentProject;
        while (p.getParent() != null) {
            p = p.getParent();
        }
        return p;
    }
}
