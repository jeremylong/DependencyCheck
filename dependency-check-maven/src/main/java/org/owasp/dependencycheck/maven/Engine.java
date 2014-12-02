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

    private Engine() throws DatabaseException {
    }

    public Engine(MavenProject project) throws DatabaseException {
        this.currentProject = project;
        MavenProject parent = getRootParent();
        if ((parent != null) && (parent.getContextValue("dependency-check-data-was-updated") != null)) {
            System.setProperty("autoupdate", Boolean.FALSE.toString());
        }
        initializeEngine();
        if (getHasBeenUpdated()) {
            getRootParent().setContextValue("dependency-check-data-was-updated", Boolean.valueOf(true));
        }
    }

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

    protected void closeAnalyzer(Analyzer analyzer) {
        if ((analyzer instanceof CPEAnalyzer)) {
            if (getPreviouslyLoadedAnalyzer() == null) {
                super.closeAnalyzer(analyzer);
            }
        } else {
            super.closeAnalyzer(analyzer);
        }
    }

    public void cleanup() {
        super.cleanup();
    }

    public void cleanupFinal() {
        CPEAnalyzer cpe = getPreviouslyLoadedAnalyzer();
        if (cpe != null) {
            cpe.close();
        }
    }

    private CPEAnalyzer getPreviouslyLoadedAnalyzer() {
        CPEAnalyzer cpe = null;
        MavenProject project = getRootParent();
        if (project != null) {
            cpe = (CPEAnalyzer) project.getContextValue(CPE_ANALYZER_KEY);
        }
        return cpe;
    }

    private void storeCPEAnalyzer(CPEAnalyzer cpe) {
        MavenProject p = getRootParent();
        if (p != null) {
            p.setContextValue(CPE_ANALYZER_KEY, cpe);
        }
    }

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
