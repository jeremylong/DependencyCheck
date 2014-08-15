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

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.doxia.sink.SinkFactory;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.MavenMultiPageReport;
import org.apache.maven.reporting.MavenReportException;

/**
 * <p>
 * This is an abstract reporting mojo that enables report aggregation. Some of the code in the this class was copied
 * from the CoberturaReportMojo (http://mojo.codehaus.org/cobertura-maven-plugin/, version 2.6). The authors of the
 * CoberturaReportMojo were <a href="will.gwaltney@sas.com">Will Gwaltney</a> and
 * <a href="mailto:joakim@erdfelt.com">Joakim Erdfelt</a>. There working example of how to do report aggregation was
 * invaluable.</p>
 * <p>
 * An important point about using this abstract class is that it is intended for one to write some form of serialized
 * data (via the {@link org.owasp.dependencycheck.maven.ReportAggregationMojo#writeDataFile() }; note that the
 * <code>writeDataFile()</code> function is called automatically after either {@link org.owasp.dependencycheck.maven.ReportAggregationMojo#executeNonAggregateReport(org.apache.maven.doxia.sink.Sink,
 * org.apache.maven.doxia.sink.SinkFactory, java.util.Locale)
 * } or {@link org.owasp.dependencycheck.maven.ReportAggregationMojo#executeAggregateReport(org.apache.maven.doxia.sink.Sink,
 * org.apache.maven.doxia.sink.SinkFactory, java.util.Locale)
 * } are called. When  <code>executeAggregateReport()</code> is implemented, one can call {@link org.owasp.dependencycheck.maven.ReportAggregationMojo#getChildDataFiles()
 * } to obtain a list of the data files to aggregate.</p>
 *
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class ReportAggregationMojo extends AbstractMojo implements MavenMultiPageReport {

    /**
     * The Maven Project Object.
     */
    @Component
    private MavenProject project;

    /**
     * Logger field reference.
     */
    private static final Logger logger = Logger.getLogger(ReportAggregationMojo.class.getName());

    /**
     * List of Maven project of the current build
     */
    @Parameter(readonly = true, required = true, property = "reactorProjects")
    private List<MavenProject> reactorProjects;

    /**
     * Generate aggregate reports in multi-module projects.
     */
    @Parameter(property = "aggregate", defaultValue = "false")
    private boolean aggregate;

    private Map< MavenProject, List< MavenProject>> projectChildren;

    protected void preExecute() throws MojoExecutionException, MojoFailureException {
        if (this.canGenerateAggregateReport()) {
            buildAggregateInfo();
        }
    }

    protected abstract void performExecute() throws MojoExecutionException, MojoFailureException;

    protected void postExecute() throws MojoExecutionException, MojoFailureException {
        writeDataFile();
    }

    public final void execute() throws MojoExecutionException, MojoFailureException {
        try {
            preExecute();
            performExecute();
        } finally {
            postExecute();
        }
    }

    /**
     * Runs prior to the site report generation.
     *
     * @throws MavenReportException if a maven report exception occurs
     */
    protected void preGenerate() throws MavenReportException {
        if (canGenerateAggregateReport()) {
            buildAggregateInfo();
        }
    }

    /**
     * Executes after the site report has been generated.
     *
     * @throws MavenReportException if a maven report exception occurs
     */
    protected void postGenerate() throws MavenReportException {
        writeDataFile();
    }

    /**
     * Generates the non aggregate report.
     *
     * @param sink the sink to write the report to
     * @param sinkFactory the sink factory
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    protected abstract void executeNonAggregateReport(Sink sink, SinkFactory sinkFactory, Locale locale) throws MavenReportException;

    /**
     * Generates the aggregate Site Report.
     *
     * @param sink the sink to write the report to
     * @param sinkFactory the sink factory
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    protected abstract void executeAggregateReport(Sink sink, SinkFactory sinkFactory, Locale locale) throws MavenReportException;

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    public final void generate(@SuppressWarnings("deprecation") org.codehaus.doxia.sink.Sink sink, Locale locale) throws MavenReportException {
        generate((Sink) sink, null, locale);
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param sinkFactory the sink factory
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    public final void generate(Sink sink, SinkFactory sinkFactory, Locale locale) throws MavenReportException {
        try {
            preGenerate();
            if (canGenerateNonAggregateReport()) {
                executeNonAggregateReport(sink, sinkFactory, locale);
            }

            if (canGenerateAggregateReport()) {
                executeAggregateReport(sink, sinkFactory, locale);
            }
        } finally {
            postGenerate();
        }
    }

    /**
     * Returns whether or not the mojo can generate a non-aggregate report for this project.
     *
     * @return <code>true</code> if a non-aggregate report can be generated, otherwise <code>false</code>
     */
    protected abstract boolean canGenerateNonAggregateReport();

    /**
     * Returns whether or not we can generate any aggregate reports at this time.
     *
     * @return <code>true</code> if an aggregate report can be generated, otherwise <code>false</code>
     */
    protected abstract boolean canGenerateAggregateReport();

    /**
     * Returns the data file's names.
     *
     * @return the data file's name
     */
    protected abstract String getDataFileName();

    /**
     * Writes the data file to disk in the target directory.
     *
     */
    protected abstract void writeDataFile();

    /**
     * Collects the information needed for building aggregate reports.
     */
    private void buildAggregateInfo() {
        if (projectChildren != null) {
            // already did this work
            return;
        }
        logger.warning("building aggregate info");
        boolean test = reactorProjects == null;
        logger.warning("Reactor is " + test);

        // build parent-child map
        projectChildren = new HashMap<MavenProject, List<MavenProject>>();
        for (MavenProject proj : reactorProjects) {
            List<MavenProject> depList = projectChildren.get(proj.getParent());
            if (depList == null) {
                depList = new ArrayList<MavenProject>();
                projectChildren.put(proj.getParent(), depList);
            }
            depList.add(proj);
        }
    }

    /**
     * Returns a list containing all the recursive, non-pom children of the given project, never <code>null</code>.
     *
     * @return a list of child projects
     */
    protected List<MavenProject> getAllChildren() {
        return getAllChildren(project);
    }

    /**
     * Returns a list containing all the recursive, non-pom children of the given project, never <code>null</code>.
     *
     * @param parentProject the parent project to collect the child project references
     * @return a list of child projects
     */
    private List<MavenProject> getAllChildren(MavenProject parentProject) {
        List<MavenProject> children = projectChildren.get(parentProject);
        if (children == null) {
            return Collections.emptyList();
        }

        List<MavenProject> result = new ArrayList<MavenProject>();
        for (MavenProject child : children) {
            if (isMultiModule(child)) {
                result.addAll(getAllChildren(child));
            } else {
                result.add(child);
            }
        }
        return result;
    }

    /**
     * Returns any existing output files from the current projects children.
     *
     * @param projects the list of projects to obtain the output files from
     * @return a list of output files
     */
    protected List<File> getChildDataFiles() {
        List<MavenProject> projects = getAllChildren();
        return getDataFiles(projects);
    }

    /**
     * Returns any existing output files from the given list of projects.
     *
     * @param projects the list of projects to obtain the output files from
     * @return a list of output files
     */
    protected List<File> getDataFiles(List<MavenProject> projects) {
        List<File> files = new ArrayList<File>();
        for (MavenProject proj : projects) {
            if (isMultiModule(proj)) {
                continue;
            }
            File outputFile = new File(proj.getBasedir(), getDataFileName());
            if (outputFile.exists()) {
                files.add(outputFile);
            } else {
                if (!isMultiModule(project)) {
                    final String msg = String.format("Unable to aggregate data for '%s' - missing data file '%s'",
                            proj.getName(), outputFile.getPath());
                    logger.warning(msg);
                }
            }
        }
        return files;
    }

    /**
     * Test if the project has pom packaging
     *
     * @param mavenProject Project to test
     * @return True if it has a pom packaging
     */
    private boolean isMultiModule(MavenProject mavenProject) {
        return "pom".equals(mavenProject.getPackaging());
    }

    /**
     * Test if the project has pom packaging
     *
     * @param mavenProject Project to test
     * @return True if it has a pom packaging
     */
    protected boolean isMultiModule() {
        return "pom".equals(project.getPackaging());
    }

    /**
     * Check whether the current project is the last project in a multi-module build. If the maven build is not a
     * multi-module project then this will always return true.
     *
     * @return <code>true</code> if the current project is the last project in a multi-module build; otherwise
     * <code>false</code>
     */
    protected boolean isLastProject() {
        return project.equals(reactorProjects.get(reactorProjects.size() - 1));
    }

    /**
     * Returns whether or not the mojo is configured to perform report aggregation.
     *
     * @return <code>true</code> if report aggregation is enabled; otherwise <code>false</code>
     */
    public boolean isAggregate() {
        return aggregate;
    }
}
