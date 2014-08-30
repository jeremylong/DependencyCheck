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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.MavenReport;
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
public abstract class ReportAggregationMojo extends AbstractMojo implements MavenReport {

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

    /**
     * Sets whether or not the external report format should be used.
     */
    @Parameter(property = "metaFileName", defaultValue = "dependency-check.ser", required = true)
    private String dataFileName;
    /**
     * Specifies the destination directory for the generated Dependency-Check report. This generally maps to
     * "target/site".
     */
    @Parameter(property = "reportOutputDirectory", defaultValue = "${project.reporting.outputDirectory}", required = true)
    private File reportOutputDirectory;

    /**
     * Sets the Reporting output directory.
     *
     * @param directory the output directory
     */
    @Override
    public void setReportOutputDirectory(File directory) {
        reportOutputDirectory = directory;
    }

    /**
     * Returns the output directory.
     *
     * @return the output directory
     */
    @Override
    public File getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    public File getReportOutputDirectory(MavenProject project) {
        Object o = project.getContextValue(getOutputDirectoryContextKey());
        if (o != null && o instanceof File) {
            return (File) o;
        }
        return null;
    }

    /**
     * Returns whether this is an external report. This method always returns true.
     *
     * @return <code>true</code>
     */
    @Override
    public final boolean isExternalReport() {
        return true;
    }

    /**
     * The collection of child projects.
     */
    private final Map< MavenProject, Set<MavenProject>> projectChildren = new HashMap<MavenProject, Set<MavenProject>>();

    protected void preExecute() throws MojoExecutionException, MojoFailureException {
        buildAggregateInfo();
    }

    protected abstract void performExecute() throws MojoExecutionException, MojoFailureException;

    protected void postExecute() throws MojoExecutionException, MojoFailureException {
        File written = writeDataFile();
        if (written != null) {
            project.setContextValue(getDataFileContextKey(), written.getAbsolutePath());
        }
    }

    protected String getDataFileContextKey() {
        return "dependency-check-path-" + this.getDataFileName();
    }

    protected String getOutputDirectoryContextKey() {
        return "dependency-output-dir-" + this.getDataFileName();
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
        buildAggregateInfo();

        project.setContextValue(getOutputDirectoryContextKey(), getReportOutputDirectory());
    }

    /**
     * Executes after the site report has been generated.
     *
     * @throws MavenReportException if a maven report exception occurs
     */
    protected void postGenerate() throws MavenReportException {
        File written = writeDataFile();
        if (written != null) {
            project.setContextValue(getDataFileContextKey(), written.getAbsolutePath());
        }
    }

    /**
     * Generates the non aggregate report.
     *
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    protected abstract void executeNonAggregateReport(Locale locale) throws MavenReportException;

    /**
     * Generates the aggregate Site Report.
     *
     * @param project the maven project used to generate the aggregate report
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    protected abstract void executeAggregateReport(MavenProject project, Locale locale) throws MavenReportException;

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     * @deprecated use {@link #generate(org.apache.maven.doxia.sink.Sink, java.util.Locale) instead.
     */
    @Deprecated
    public final void generate(@SuppressWarnings("deprecation") org.codehaus.doxia.sink.Sink sink, Locale locale) throws MavenReportException {
        generate((Sink) sink, locale);
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a maven report exception occurs
     */
    public final void generate(Sink sink, Locale locale) throws MavenReportException {
        try {
            preGenerate();
            if (canGenerateNonAggregateReport()) {
                executeNonAggregateReport(locale);
            }

            if (canGenerateAggregateReport()) {
                for (MavenProject proj : reactorProjects) {
                    if (!isMultiModule(proj)) {
                        continue;
                    }
                    executeAggregateReport(proj, locale);
                }
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
     * Returns the name of the data file that contains the serialized data.
     *
     * @return the name of the data file that contains the serialized data
     */
    protected String getDataFileName() {
        return dataFileName;
    }

    /**
     * Writes the data file to disk in the target directory.
     *
     * @return the File object referencing the data file that was written
     */
    protected abstract File writeDataFile();

    /**
     * Collects the information needed for building aggregate reports.
     */
    private void buildAggregateInfo() {
        // build parent-child map
        for (MavenProject proj : reactorProjects) {
            Set<MavenProject> depList = projectChildren.get(proj.getParent());
            if (depList == null) {
                depList = new HashSet<MavenProject>();
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
    protected List<MavenProject> getAllChildren(MavenProject parentProject) {
        Set<MavenProject> children = projectChildren.get(parentProject);
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

    protected List<File> getAllChildDataFiles(MavenProject project) {
        List<MavenProject> children = getAllChildren(project);
        return getDataFiles(children);
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
            Object path = project.getContextValue(getDataFileContextKey());
            if (path == null) {
                final String msg = String.format("Unable to aggregate data for '%s' - aggregate data file was not generated",
                        proj.getName());
                logger.warning(msg);
            } else {
                File outputFile = new File((String) path);
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
        }
        return files;
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
     * Test if the current project has pom packaging
     *
     * @param mavenProject Project to test
     * @return <code>true</code> if it has a pom packaging; otherwise <code>false</code>
     */
    protected boolean isMultiModule() {
        return isMultiModule(project);
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

    /**
     * Returns a reference to the current project. This method is used instead of auto-binding the project via component
     * annotation in concrete implementations of this. If the child has a <code>@Component MavenProject project;</code>
     * defined then the abstract class (i.e. this class) will not have access to the current project (just the way Maven
     * works with the binding).
     *
     * @return
     */
    protected MavenProject getProject() {
        return project;
    }
}
