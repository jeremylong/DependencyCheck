/*
 * This file is part of dependency-check-maven.
 *
 * Dependency-check-maven is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-maven is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-maven. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.maven.doxia.sink.SinkFactory;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.reporting.MavenMultiPageReport;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.plugin.MojoFailureException;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.LogUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Maven Plugin that checks project dependencies to see if they have any known
 * published vulnerabilities.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
@Mojo(name = "check", defaultPhase = LifecyclePhase.COMPILE, threadSafe = true,
        requiresDependencyResolution = ResolutionScope.RUNTIME_PLUS_SYSTEM,
        requiresOnline = true)
public class DependencyCheckMojo extends AbstractMojo implements MavenMultiPageReport {

    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "mojo.properties";
    /**
     * Name of the logging properties file.
     */
    private static final String LOG_PROPERTIES_FILE = "log.properties";
    /**
     * The name of the test scope.
     */
    public static final String TEST_SCOPE = "test";
    /**
     * System specific new line character.
     */
    private static final String NEW_LINE = System.getProperty("line.separator", "\n").intern();
    // <editor-fold defaultstate="collapsed" desc="Maven bound parameters and components">
    /**
     * The Maven Project Object.
     */
    @Component
    private MavenProject project;
    /**
     * The name of the site report destination.
     */
    @Parameter(property = "report-name", defaultValue = "dependency-check-report")
    private String reportName;
    /**
     * The path to the verbose log
     */
    @Parameter(property = "logfile", defaultValue = "")
    private String logFile;
    /**
     * The name of the report to be displayed in the Maven Generated Reports
     * page
     */
    @Parameter(property = "name", defaultValue = "Dependency-Check")
    private String name;
    /**
     * The description of the Dependency-Check report to be displayed in the
     * Maven Generated Reports page
     */
    @Parameter(property = "description", defaultValue = "A report providing details on any published "
            + "vulnerabilities within project dependencies. This report is a best effort but may contain "
            + "false positives and false negatives.")
    private String description;
    /**
     * Specifies the destination directory for the generated Dependency-Check
     * report.
     */
    @Parameter(property = "reportOutputDirectory", defaultValue = "${project.reporting.outputDirectory}", required = true)
    private File reportOutputDirectory;
    /**
     * Specifies if the build should be failed if a CVSS score above a specified
     * level is identified. The default is 11 which means since the CVSS scores
     * are 0-10, by default the build will never fail.
     */
    @Parameter(property = "failBuildOnCVSS", defaultValue = "11", required = true)
    private float failBuildOnCVSS = 11;
    /**
     * The output directory.
     */
    @Parameter(defaultValue = "${project.build.directory}", required = true)
    private File outputDirectory;
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not
     * recommended that this be turned to false. Default is true.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "autoupdate", defaultValue = "true", required = true)
    private boolean autoUpdate = true;
    /**
     * The report format to be generated (HTML, XML, VULN, ALL). This
     * configuration option has no affect if using this within the Site plugin
     * unless the externalReport is set to true. Default is HTML.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "format", defaultValue = "HTML", required = true)
    private String format = "HTML";
    /**
     * Sets whether or not the external report format should be used.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "externalReport", defaultValue = "false", required = true)
    private boolean externalReport = false;
    /**
     * The Proxy URL.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyUrl", defaultValue = "", required = false)
    private String proxyUrl = null;
    /**
     * The Proxy Port.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyPort", defaultValue = "", required = false)
    private String proxyPort = null;
    /**
     * The Proxy username.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyUsername", defaultValue = "", required = false)
    private String proxyUsername = null;
    /**
     * The Proxy password.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyPassword", defaultValue = "", required = false)
    private String proxyPassword = null;
    /**
     * The Connection Timeout.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "connectionTimeout", defaultValue = "", required = false)
    private String connectionTimeout = null;
    /**
     * The Connection Timeout.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "suppressionFile", defaultValue = "", required = false)
    private String suppressionFile = null;
    /**
     * Flag indicating whether or not to show a summary in the output.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "showSummary", defaultValue = "true", required = false)
    private boolean showSummary = true;
    // </editor-fold>

    /**
     * Executes the Dependency-Check on the dependent libraries.
     *
     * @return the Engine used to scan the dependencies.
     */
    private Engine executeDependencyCheck() {

        final InputStream in = DependencyCheckMojo.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);

        populateSettings();
        final Engine engine = new Engine();
        final Set<Artifact> artifacts = project.getArtifacts();
        for (Artifact a : artifacts) {
            if (!TEST_SCOPE.equals(a.getScope())) {
                engine.scan(a.getFile().getAbsolutePath());
            }
        }
        engine.analyzeDependencies();
        return engine;
    }

    /**
     * Generates the reports for a given dependency-check engine.
     *
     * @param engine a dependency-check engine
     */
    private void generateExternalReports(Engine engine) {
        final ReportGenerator r = new ReportGenerator(project.getName(), engine.getDependencies(), engine.getAnalyzers());
        try {
            r.generateReports(outputDirectory.getCanonicalPath(), format);
        } catch (IOException ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.SEVERE, "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.SEVERE, "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, null, ex);
        }
    }

    /**
     * Generates a dependency-check report using the Maven Site format.
     *
     * @param engine the engine used to scan the dependencies
     * @param sink the sink to write the data to
     */
    private void generateMavenSiteReport(final Engine engine, Sink sink) {
        final List<Dependency> dependencies = engine.getDependencies();

        writeSiteReportHeader(sink, project.getName());
        writeSiteReportTOC(sink, dependencies);

        int cnt = 0;
        for (Dependency d : dependencies) {
            writeSiteReportDependencyHeader(sink, d);
            cnt = writeSiteReportDependencyAnalysisExceptions(d, cnt, sink);
            cnt = writeSiteReportDependencyEvidenceUsed(d, cnt, sink);
            cnt = writeSiteReportDependencyRelatedDependencies(d, cnt, sink);
            writeSiteReportDependencyIdentifiers(d, sink);
            writeSiteReportDependencyVulnerabilities(d, sink, cnt);
        }
        sink.body_();
    }

    // <editor-fold defaultstate="collapsed" desc="various writeXXXXX methods to generate the Site Report">
    /**
     * Writes the vulnerabilities to the site report.
     *
     * @param d the dependency
     * @param sink the sink to write the data to
     * @param collapsibleHeaderCount the collapsible header count
     */
    private void writeSiteReportDependencyVulnerabilities(Dependency d, Sink sink, int collapsibleHeaderCount) {
        int cnt = collapsibleHeaderCount;
        if (d.getVulnerabilities() != null && !d.getVulnerabilities().isEmpty()) {
            for (Vulnerability v : d.getVulnerabilities()) {

                sink.paragraph();
                sink.bold();
                try {
                    sink.link("http://web.nvd.nist.gov/view/vuln/detail?vulnId=" + URLEncoder.encode(v.getName(), "US-ASCII"));
                    sink.text(v.getName());
                    sink.link_();
                    sink.bold_();
                } catch (UnsupportedEncodingException ex) {
                    sink.text(v.getName());
                    sink.bold_();
                    sink.lineBreak();
                    sink.text("http://web.nvd.nist.gov/view/vuln/detail?vulnId=" + v.getName());
                }
                sink.paragraph_();
                sink.paragraph();
                sink.text("Severity: ");
                if (v.getCvssScore() < 4.0) {
                    sink.text("Low");
                } else {
                    if (v.getCvssScore() >= 7.0) {
                        sink.text("High");
                    } else {
                        sink.text("Medium");
                    }
                }
                sink.lineBreak();
                sink.text("CVSS Score: " + v.getCvssScore());
                if (v.getCwe() != null && !v.getCwe().isEmpty()) {
                    sink.lineBreak();
                    sink.text("CWE: ");
                    sink.text(v.getCwe());
                }
                sink.paragraph_();
                sink.paragraph();
                sink.text(v.getDescription());
                if (v.getReferences() != null && !v.getReferences().isEmpty()) {
                    sink.list();
                    for (Reference ref : v.getReferences()) {
                        sink.listItem();
                        sink.text(ref.getSource());
                        sink.text(" - ");
                        sink.link(ref.getUrl());
                        sink.text(ref.getName());
                        sink.link_();
                        sink.listItem_();
                    }
                    sink.list_();
                }
                sink.paragraph_();
                if (v.getVulnerableSoftware() != null && !v.getVulnerableSoftware().isEmpty()) {
                    sink.paragraph();

                    cnt += 1;
                    sink.rawText("Vulnerable Software <a href=\"javascript:toggleElement(this, 'vulnSoft" + cnt + "')\">[-]</a>");
                    sink.rawText("<div id=\"vulnSoft" + cnt + "\" style=\"display:block\">");
                    sink.list();
                    for (VulnerableSoftware vs : v.getVulnerableSoftware()) {
                        sink.listItem();
                        try {
                            sink.link("http://web.nvd.nist.gov/view/vuln/search-results?cpe=" + URLEncoder.encode(vs.getName(), "US-ASCII"));
                            sink.text(vs.getName());
                            sink.link_();
                            if (vs.hasPreviousVersion()) {
                                sink.text(" and all previous versions.");
                            }
                        } catch (UnsupportedEncodingException ex) {
                            sink.text(vs.getName());
                            if (vs.hasPreviousVersion()) {
                                sink.text(" and all previous versions.");
                            }
                            sink.text(" (http://web.nvd.nist.gov/view/vuln/search-results?cpe=" + vs.getName() + ")");
                        }

                        sink.listItem_();
                    }
                    sink.list_();
                    sink.rawText("</div>");
                    sink.paragraph_();
                }
            }
        }
    }

    /**
     * Writes the identifiers to the site report.
     *
     * @param d the dependency
     * @param sink the sink to write the data to
     */
    private void writeSiteReportDependencyIdentifiers(Dependency d, Sink sink) {
        if (d.getIdentifiers() != null && !d.getIdentifiers().isEmpty()) {
            sink.sectionTitle4();
            sink.text("Identifiers");
            sink.sectionTitle4_();
            sink.list();
            for (Identifier i : d.getIdentifiers()) {
                sink.listItem();
                sink.text(i.getType());
                sink.text(": ");
                if (i.getUrl() != null && i.getUrl().length() > 0) {
                    sink.link(i.getUrl());
                    sink.text(i.getValue());
                    sink.link_();
                } else {
                    sink.text(i.getValue());
                }
                if (i.getDescription() != null && i.getDescription().length() > 0) {
                    sink.lineBreak();
                    sink.text(i.getDescription());
                }
                sink.listItem_();
            }
            sink.list_();
        }
    }

    /**
     * Writes the related dependencies to the site report.
     *
     * @param d the dependency
     * @param sink the sink to write the data to
     * @param collapsibleHeaderCount the collapsible header count
     * @return the collapsible header count
     */
    private int writeSiteReportDependencyRelatedDependencies(Dependency d, int collapsibleHeaderCount, Sink sink) {
        int cnt = collapsibleHeaderCount;
        if (d.getRelatedDependencies() != null && !d.getRelatedDependencies().isEmpty()) {
            cnt += 1;
            sink.sectionTitle4();
            sink.rawText("Related Dependencies <a href=\"javascript:toggleElement(this, 'related" + cnt + "')\">[+]</a>");
            sink.sectionTitle4_();
            sink.rawText("<div id=\"related" + cnt + "\" style=\"display:none\">");
            sink.list();
            for (Dependency r : d.getRelatedDependencies()) {
                sink.listItem();
                sink.text(r.getFileName());
                sink.list();
                writeListItem(sink, "File Path: " + r.getFilePath());
                writeListItem(sink, "SHA1: " + r.getSha1sum());
                writeListItem(sink, "MD5: " + r.getMd5sum());
                sink.list_();
                sink.listItem_();
            }
            sink.list_();
            sink.rawText("</div>");
        }
        return cnt;
    }

    /**
     * Writes the evidence used to the site report.
     *
     * @param d the dependency
     * @param sink the sink to write the data to
     * @param collapsibleHeaderCount the collapsible header count
     * @return the collapsible header count
     */
    private int writeSiteReportDependencyEvidenceUsed(Dependency d, int collapsibleHeaderCount, Sink sink) {
        int cnt = collapsibleHeaderCount;
        if (d.getEvidenceUsed() != null && d.getEvidenceUsed().size() > 0) {
            cnt += 1;
            sink.sectionTitle4();
            sink.rawText("Evidence Collected <a href=\"javascript:toggleElement(this, 'evidence" + cnt + "')\">[+]</a>");
            sink.sectionTitle4_();
            sink.rawText("<div id=\"evidence" + cnt + "\" style=\"display:none\">");
            sink.table();
            sink.tableRow();
            writeTableHeaderCell(sink, "Source");
            writeTableHeaderCell(sink, "Name");
            writeTableHeaderCell(sink, "Value");
            sink.tableRow_();
            for (Evidence e : d.getEvidenceUsed()) {
                sink.tableRow();
                writeTableCell(sink, e.getSource());
                writeTableCell(sink, e.getName());
                writeTableCell(sink, e.getValue());
                sink.tableRow_();
            }
            sink.table_();
            sink.rawText("</div>");
        }
        return cnt;
    }

    /**
     * Writes the analysis exceptions generated during analysis to the site
     * report.
     *
     * @param d the dependency
     * @param sink the sink to write the data to
     * @param collapsibleHeaderCount the collapsible header count
     * @return the collapsible header count
     */
    private int writeSiteReportDependencyAnalysisExceptions(Dependency d, int collapsibleHeaderCount, Sink sink) {
        int cnt = collapsibleHeaderCount;
        if (d.getAnalysisExceptions() != null && !d.getAnalysisExceptions().isEmpty()) {
            cnt += 1;
            sink.sectionTitle4();
            sink.rawText("<font style=\"color:red\">Errors occurred during analysis:</font> <a href=\"javascript:toggleElement(this, 'errors"
                    + cnt + "')\">[+]</a>");
            sink.sectionTitle4_();
            sink.rawText("<div id=\"errors" + cnt + "\">");
            sink.list();
            for (Exception e : d.getAnalysisExceptions()) {
                sink.listItem();
                sink.text(e.getMessage());
                sink.listItem_();
            }
            sink.list_();
            sink.rawText("</div>");
        }
        return cnt;
    }

    /**
     * Writes the dependency header to the site report.
     *
     * @param d the dependency
     * @param sink the sink to write the data to
     */
    private void writeSiteReportDependencyHeader(Sink sink, Dependency d) {
        sink.sectionTitle2();
        sink.anchor("sha1" + d.getSha1sum());
        sink.text(d.getFileName());
        sink.anchor_();
        sink.sectionTitle2_();
        if (d.getDescription() != null && d.getDescription().length() > 0) {
            sink.paragraph();
            sink.bold();
            sink.text("Description: ");
            sink.bold_();
            sink.text(d.getDescription());
            sink.paragraph_();
        }
        if (d.getLicense() != null && d.getLicense().length() > 0) {
            sink.paragraph();
            sink.bold();
            sink.text("License: ");
            sink.bold_();
            if (d.getLicense().startsWith("http://") && !d.getLicense().contains(" ")) {
                sink.link(d.getLicense());
                sink.text(d.getLicense());
                sink.link_();
            } else {
                sink.text(d.getLicense());
            }
            sink.paragraph_();
        }
    }

    /**
     * Adds a list item to the site report.
     *
     * @param sink the sink to write the data to
     * @param text the text to write
     */
    private void writeListItem(Sink sink, String text) {
        sink.listItem();
        sink.text(text);
        sink.listItem_();
    }

    /**
     * Adds a table cell to the site report.
     *
     * @param sink the sink to write the data to
     * @param text the text to write
     */
    private void writeTableCell(Sink sink, String text) {
        sink.tableCell();
        sink.text(text);
        sink.tableCell_();
    }

    /**
     * Adds a table header cell to the site report.
     *
     * @param sink the sink to write the data to
     * @param text the text to write
     */
    private void writeTableHeaderCell(Sink sink, String text) {
        sink.tableHeaderCell();
        sink.text(text);
        sink.tableHeaderCell_();
    }

    /**
     * Writes the TOC for the site report.
     *
     * @param sink the sink to write the data to
     * @param dependencies the dependencies that are being reported on
     */
    private void writeSiteReportTOC(Sink sink, final List<Dependency> dependencies) {
        sink.list();
        for (Dependency d : dependencies) {
            sink.listItem();
            sink.link("#sha1" + d.getSha1sum());
            sink.text(d.getFileName());
            sink.link_();
            if (!d.getVulnerabilities().isEmpty()) {
                sink.rawText(" <font style=\"color:red\">•</font>");
            }
            if (!d.getRelatedDependencies().isEmpty()) {
                sink.list();
                for (Dependency r : d.getRelatedDependencies()) {
                    writeListItem(sink, r.getFileName());
                }
                sink.list_();
            }
            sink.listItem_();
        }
        sink.list_();
    }

    /**
     * Writes the site report header.
     *
     * @param sink the sink to write the data to
     * @param projectName the name of the project
     */
    private void writeSiteReportHeader(Sink sink, String projectName) {
        sink.head();
        sink.title();
        sink.text("Dependency-Check Report: " + projectName);
        sink.title_();
        sink.head_();
        sink.body();
        sink.rawText("<script type=\"text/javascript\">");
        sink.rawText("function toggleElement(el, targetId) {");
        sink.rawText("if (el.innerText == '[+]') {");
        sink.rawText("    el.innerText = '[-]';");
        sink.rawText("    document.getElementById(targetId).style.display='block';");
        sink.rawText("} else {");
        sink.rawText("    el.innerText = '[+]';");
        sink.rawText("    document.getElementById(targetId).style.display='none';");
        sink.rawText("}");

        sink.rawText("}");
        sink.rawText("</script>");
        sink.section1();
        sink.sectionTitle1();
        sink.text("Project: " + projectName);
        sink.sectionTitle1_();
        sink.date();
        final Date now = new Date();
        sink.text(DateFormat.getDateTimeInstance().format(now));
        sink.date_();
        sink.section1_();
    }
    // </editor-fold>

    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy url, port, and connection timeout.
     */
    private void populateSettings() {
        InputStream mojoProperties = null;
        try {
            mojoProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            Settings.mergeProperties(mojoProperties);
        } catch (IOException ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.WARNING, "Unable to load the dependency-check ant task.properties file.");
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, null, ex);
        } finally {
            if (mojoProperties != null) {
                try {
                    mojoProperties.close();
                } catch (IOException ex) {
                    Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }

        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);

        if (proxyUrl != null && !proxyUrl.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_URL, proxyUrl);
        }
        if (proxyPort != null && !proxyPort.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_PORT, proxyPort);
        }
        if (proxyUsername != null && !proxyUsername.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_USERNAME, proxyUsername);
        }
        if (proxyPassword != null && !proxyPassword.isEmpty()) {
            Settings.setString(Settings.KEYS.PROXY_PASSWORD, proxyPassword);
        }
        if (connectionTimeout != null && !connectionTimeout.isEmpty()) {
            Settings.setString(Settings.KEYS.CONNECTION_TIMEOUT, connectionTimeout);
        }
        if (suppressionFile != null && !suppressionFile.isEmpty()) {
            Settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile);
        }
    }

    /**
     * Executes the dependency-check and generates the report.
     *
     * @throws MojoExecutionException if a maven exception occurs
     * @throws MojoFailureException thrown if a CVSS score is found that is
     * higher then the configured level
     */
    public void execute() throws MojoExecutionException, MojoFailureException {
        final Engine engine = executeDependencyCheck();
        generateExternalReports(engine);
        if (this.failBuildOnCVSS <= 10) {
            checkForFailure(engine.getDependencies());
        }
        if (this.showSummary) {
            showSummary(engine.getDependencies());
        }
    }

    /**
     * Generates the Dependency-Check Site Report.
     *
     * @param sink the sink to write the report to
     * @param locale the locale to use when generating the report
     * @throws MavenReportException if a Maven report exception occurs
     */
    public void generate(@SuppressWarnings("deprecation") org.codehaus.doxia.sink.Sink sink,
            Locale locale) throws MavenReportException {
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
    public void generate(Sink sink, SinkFactory sinkFactory, Locale locale) throws MavenReportException {
        final Engine engine = executeDependencyCheck();
        generateMavenSiteReport(engine, sink);
    }

    // <editor-fold defaultstate="collapsed" desc="required setter/getter methods">
    /**
     * Returns the output name.
     *
     * @return the output name
     */
    public String getOutputName() {
        return reportName;
    }

    /**
     * Returns the category name.
     *
     * @return the category name
     */
    public String getCategoryName() {
        return MavenReport.CATEGORY_PROJECT_REPORTS;
    }

    /**
     * Returns the report name.
     *
     * @param locale the location
     * @return the report name
     */
    public String getName(Locale locale) {
        return name;
    }

    /**
     * Sets the Reporting output directory.
     *
     * @param directory the output directory
     */
    public void setReportOutputDirectory(File directory) {
        reportOutputDirectory = directory;
    }

    /**
     * Returns the output directory.
     *
     * @return the output directory
     */
    public File getReportOutputDirectory() {
        return reportOutputDirectory;
    }

    /**
     * Gets the description of the Dependency-Check report to be displayed in
     * the Maven Generated Reports page.
     *
     * @param locale The Locale to get the description for
     * @return the description
     */
    public String getDescription(Locale locale) {
        return description;
    }

    /**
     * Returns whether this is an external report.
     *
     * @return true or false;
     */
    public boolean isExternalReport() {
        return externalReport;
    }

    /**
     * Returns whether or not the plugin can generate a report.
     *
     * @return true
     */
    public boolean canGenerateReport() {
        return true;
    }
    // </editor-fold>

    /**
     * Checks to see if a vulnerability has been identified with a CVSS score
     * that is above the threshold set in the configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws MojoFailureException thrown if a CVSS score is found that is
     * higher then the threshold set
     */
    private void checkForFailure(List<Dependency> dependencies) throws MojoFailureException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            for (Vulnerability v : d.getVulnerabilities()) {
                if (v.getCvssScore() >= failBuildOnCVSS) {
                    if (ids.length() == 0) {
                        ids.append(v.getName());
                    } else {
                        ids.append(", ").append(v.getName());
                    }
                }
            }
        }
        if (ids.length() > 0) {
            final String msg = String.format("%n%nDependency-Check Failure:%n"
                    + "One or more dependencies were identified with vulnerabilities that have a CVSS score greater then '%.1f': %s%n"
                    + "See the dependency-check report for more details.%n%n", failBuildOnCVSS, ids.toString());
            throw new MojoFailureException(msg);
        }
    }

    /**
     * Generates a warning message listing a summary of dependencies and their
     * associated CPE and CVE entries.
     *
     * @param dependencies a list of dependency objects
     */
    private void showSummary(List<Dependency> dependencies) {
        final StringBuilder summary = new StringBuilder();
        for (Dependency d : dependencies) {
            boolean firstEntry = true;
            final StringBuilder ids = new StringBuilder();
            for (Vulnerability v : d.getVulnerabilities()) {
                if (firstEntry) {
                    firstEntry = false;
                } else {
                    ids.append(", ");
                }
                ids.append(v.getName());
            }
            if (ids.length() > 0) {
                summary.append(d.getFileName()).append(" (");
                firstEntry = true;
                for (Identifier id : d.getIdentifiers()) {
                    if (firstEntry) {
                        firstEntry = false;
                    } else {
                        summary.append(", ");
                    }
                    summary.append(id.getValue());
                }
                summary.append(") : ").append(ids).append(NEW_LINE);
            }
        }
        if (summary.length() > 0) {
            final String msg = String.format("%n%n"
                    + "One or more dependencies were identified with known vulnerabilities:%n%n%s"
                    + "%n%nSee the dependency-check report for more details.%n%n", summary.toString());
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.WARNING, msg);
        }
    }
}
