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
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.doxia.sink.SinkFactory;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.MavenMultiPageReport;
import org.apache.maven.reporting.MavenReport;
import org.apache.maven.reporting.MavenReportException;
import org.apache.maven.settings.Proxy;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
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
 * Maven Plugin that checks project dependencies to see if they have any known published vulnerabilities.
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
     * The path to the verbose log.
     */
    @Parameter(property = "logfile", defaultValue = "")
    private String logFile;
    /**
     * The name of the report to be displayed in the Maven Generated Reports page.
     */
    @Parameter(property = "name", defaultValue = "Dependency-Check")
    private String name;
    /**
     * The description of the Dependency-Check report to be displayed in the Maven Generated Reports page.
     */
    @Parameter(property = "description", defaultValue = "A report providing details on any published "
            + "vulnerabilities within project dependencies. This report is a best effort but may contain "
            + "false positives and false negatives.")
    private String description;
    /**
     * Specifies the destination directory for the generated Dependency-Check report.
     */
    @Parameter(property = "reportOutputDirectory", defaultValue = "${project.reporting.outputDirectory}", required = true)
    private File reportOutputDirectory;
    /**
     * Specifies if the build should be failed if a CVSS score above a specified level is identified. The default is 11
     * which means since the CVSS scores are 0-10, by default the build will never fail.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "failBuildOnCVSS", defaultValue = "11", required = true)
    private float failBuildOnCVSS = 11;
    /**
     * The output directory.
     */
    @Parameter(defaultValue = "${project.build.directory}", required = true)
    private File outputDirectory;
    /**
     * Sets whether auto-updating of the NVD CVE/CPE data is enabled. It is not recommended that this be turned to
     * false. Default is true.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "autoupdate", defaultValue = "true", required = true)
    private boolean autoUpdate = true;
    /**
     * The report format to be generated (HTML, XML, VULN, ALL). This configuration option has no affect if using this
     * within the Site plugin unless the externalReport is set to true. Default is HTML.
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
     * @deprecated Please use mavenSettings instead
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyUrl", defaultValue = "", required = false)
    @Deprecated
    private String proxyUrl = null;
    
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "mavenSettings", defaultValue = "${settings}", required = false)
    private org.apache.maven.settings.Settings mavenSettings;
    
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "mavenSettingsProxyId", required = false)
    private String mavenSettingsProxyId;
    
    
    /**
     * The Proxy Port.
     * @deprecated Please use mavenSettings instead
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyPort", defaultValue = "", required = false)
    @Deprecated
    private String proxyPort = null;
    /**
     * The Proxy username.
     * @deprecated Please use mavenSettings instead
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyUsername", defaultValue = "", required = false)
    @Deprecated
    private String proxyUsername = null;
    /**
     * The Proxy password.
     * @deprecated Please use mavenSettings instead
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "proxyPassword", defaultValue = "", required = false)
    @Deprecated
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
    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nexusAnalyzerEnabled", defaultValue = "true", required = false)
    private boolean nexusAnalyzerEnabled = true;
    /**
     * Whether or not the Nexus Analyzer is enabled.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nexusUrl", defaultValue = "", required = false)
    private String nexusUrl;
    /**
     * Whether or not the configured proxy is used to connect to Nexus.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "nexusUsesProxy", defaultValue = "true", required = false)
    private boolean nexusUsesProxy = true;
    /**
     * The database connection string.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "connectionString", defaultValue = "", required = false)
    private String connectionString;
    /**
     * The database driver name. An example would be org.h2.Driver.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databaseDriverName", defaultValue = "", required = false)
    private String databaseDriverName;
    /**
     * The path to the database driver if it is not on the class path.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databaseDriverPath", defaultValue = "", required = false)
    private String databaseDriverPath;
    /**
     * The database user name.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databaseUser", defaultValue = "", required = false)
    private String databaseUser;
    /**
     * The password to use when connecting to the database.
     */
    @SuppressWarnings({"CanBeFinal", "FieldCanBeLocal"})
    @Parameter(property = "databasePassword", defaultValue = "", required = false)
    private String databasePassword;
    /**
     * A comma-separated list of file extensions to add to analysis next to jar, zip, ....
     */
    @Parameter(property = "zipExtensions", required = false)
    private String zipExtensions;
    /**
     * Skip Analisys for Test Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipTestScope", defaultValue = "true", required = false)
    private boolean skipTestScope = true;
    /**
     * Skip Analisys for Runtime Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipRuntimeScope", defaultValue = "false", required = false)
    private boolean skipRuntimeScope = false;
    /**
     * Skip Analisys for Provided Scope Dependencies.
     */
    @SuppressWarnings("CanBeFinal")
    @Parameter(property = "skipProvidedScope", defaultValue = "false", required = false)
    private boolean skipProvidedScope = false;
    /**
     * The data directory, hold DC SQL DB.
     */
    @Parameter(property = "dataDirectory", defaultValue = "", required = false)
    private String dataDirectory;
    /**
     * Data Mirror URL for CVE 1.2.
     */
    @Parameter(property = "cveUrl12Modified", defaultValue = "", required = false)
    private String cveUrl12Modified;
    /**
     * Data Mirror URL for CVE 2.0.
     */
    @Parameter(property = "cveUrl20Modified", defaultValue = "", required = false)
    private String cveUrl20Modified;
    /**
     * Base Data Mirror URL for CVE 1.2.
     */
    @Parameter(property = "cveUrl12Base", defaultValue = "", required = false)
    private String cveUrl12Base;
    /**
     * Data Mirror URL for CVE 2.0.
     */
    @Parameter(property = "cveUrl20Base", defaultValue = "", required = false)
    private String cveUrl20Base;

    /**
     * The path to mono for .NET Assembly analysis on non-windows systems.
     */
    @Parameter(property = "pathToMono", defaultValue = "", required = false)
    private String pathToMono;

    // </editor-fold>
    /**
     * Executes the Dependency-Check on the dependent libraries.
     *
     * @return the Engine used to scan the dependencies.
     * @throws DatabaseException thrown if there is an exception connecting to the database
     */
    private Engine executeDependencyCheck() throws DatabaseException {

        final InputStream in = DependencyCheckMojo.class.getClassLoader().getResourceAsStream(LOG_PROPERTIES_FILE);
        LogUtils.prepareLogger(in, logFile);

        populateSettings();
        Engine engine = null;
        try {
            engine = new Engine();
            final Set<Artifact> artifacts = project.getArtifacts();
            for (Artifact a : artifacts) {
                if (skipTestScope && Artifact.SCOPE_TEST.equals(a.getScope())) {
                    continue;
                }

                if (skipProvidedScope && Artifact.SCOPE_PROVIDED.equals(a.getScope())) {
                    continue;
                }

                if (skipRuntimeScope && !Artifact.SCOPE_RUNTIME.equals(a.getScope())) {
                    continue;
                }

                engine.scan(a.getFile().getAbsolutePath());
            }
            engine.analyzeDependencies();
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }
        return engine;
    }

    /**
     * Generates the reports for a given dependency-check engine.
     *
     * @param engine a dependency-check engine
     */
    private void generateExternalReports(Engine engine) {
        DatabaseProperties prop = null;
        CveDB cve = null;
        try {
            cve = new CveDB();
            cve.open();
            prop = cve.getDatabaseProperties();
        } catch (DatabaseException ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, "Unable to retrieve DB Properties", ex);
        } finally {
            if (cve != null) {
                cve.close();
            }
        }
        final ReportGenerator r = new ReportGenerator(project.getName(), engine.getDependencies(), engine.getAnalyzers(), prop);
        try {
            r.generateReports(outputDirectory.getCanonicalPath(), format);
        } catch (IOException ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.SEVERE,
                    "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, null, ex);
        } catch (Throwable ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.SEVERE,
                    "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
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

    private String getMavenSettingsProxyUrl(Proxy proxy) {
        return new StringBuilder(proxy.getProtocol()).append( "://" ).append(proxy.getHost()).toString();
    }
    
    private Proxy getMavenProxy(){
        if (mavenSettings!=null) {
            List<Proxy> proxies = mavenSettings.getProxies();
            if ( proxies != null && proxies.size() > 0) {
                if (mavenSettingsProxyId!=null) {
                    for ( Proxy proxy : proxies )
                    {
                        if ( mavenSettingsProxyId.equalsIgnoreCase( proxy.getId() )) {
                            return proxy;
                        }
                    }
                }
                else if (proxies.size() == 1) {
                    return proxies.get(0);
                }
                else {
                    throw new IllegalStateException( "Ambigous proxy definition" );
                }
            }
        }
        
        return null;
    }
    
    /**
     * Takes the properties supplied and updates the dependency-check settings. Additionally, this sets the system
     * properties required to change the proxy url, port, and connection timeout.
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
        
        
        Proxy proxy = getMavenProxy();
        if (proxy != null) {
            Settings.setString(Settings.KEYS.PROXY_URL,getMavenSettingsProxyUrl(proxy));
            Settings.setString(Settings.KEYS.PROXY_PORT,Integer.toString(proxy.getPort()));
            String userName = proxy.getUsername();
            String password = proxy.getPassword();
            if ( userName != null && password != null){
                Settings.setString(Settings.KEYS.PROXY_USERNAME, userName);
                Settings.setString(Settings.KEYS.PROXY_PASSWORD, password);
            }
        }

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
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, nexusAnalyzerEnabled);
        if (nexusUrl != null && !nexusUrl.isEmpty()) {
            Settings.setString(Settings.KEYS.ANALYZER_NEXUS_URL, nexusUrl);
        }
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_PROXY, nexusUsesProxy);
        if (databaseDriverName != null && !databaseDriverName.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_DRIVER_NAME, databaseDriverName);
        }
        if (databaseDriverPath != null && !databaseDriverPath.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_DRIVER_PATH, databaseDriverPath);
        }
        if (connectionString != null && !connectionString.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_CONNECTION_STRING, connectionString);
        }
        if (databaseUser != null && !databaseUser.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_USER, databaseUser);
        }
        if (databasePassword != null && !databasePassword.isEmpty()) {
            Settings.setString(Settings.KEYS.DB_PASSWORD, databasePassword);
        }
        if (zipExtensions != null && !zipExtensions.isEmpty()) {
            Settings.setString(Settings.KEYS.ADDITIONAL_ZIP_EXTENSIONS, zipExtensions);
        }

        // Scope Exclusion
        Settings.setBoolean(Settings.KEYS.SKIP_TEST_SCOPE, skipTestScope);
        Settings.setBoolean(Settings.KEYS.SKIP_RUNTIME_SCOPE, skipRuntimeScope);
        Settings.setBoolean(Settings.KEYS.SKIP_PROVIDED_SCOPE, skipProvidedScope);

        // Data Directory
        if (dataDirectory != null && !dataDirectory.isEmpty()) {
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        }

        // CVE Data Mirroring
        if (cveUrl12Modified != null && !cveUrl12Modified.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_MODIFIED_12_URL, cveUrl12Modified);
        }
        if (cveUrl20Modified != null && !cveUrl20Modified.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_MODIFIED_20_URL, cveUrl20Modified);
        }
        if (cveUrl12Base != null && !cveUrl12Base.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_SCHEMA_1_2, cveUrl12Base);
        }
        if (cveUrl20Base != null && !cveUrl20Base.isEmpty()) {
            Settings.setString(Settings.KEYS.CVE_SCHEMA_2_0, cveUrl20Base);
        }
        if (pathToMono != null && !pathToMono.isEmpty()) {
            Settings.setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, pathToMono);
        }
    }

    /**
     * Executes the dependency-check and generates the report.
     *
     * @throws MojoExecutionException if a maven exception occurs
     * @throws MojoFailureException thrown if a CVSS score is found that is higher then the configured level
     */
    public void execute() throws MojoExecutionException, MojoFailureException {
        Engine engine = null;
        try {
            engine = executeDependencyCheck();
            generateExternalReports(engine);
            if (this.showSummary) {
                showSummary(engine.getDependencies());
            }
            if (this.failBuildOnCVSS <= 10) {
                checkForFailure(engine.getDependencies());
            }
        } catch (DatabaseException ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.SEVERE,
                    "Unable to connect to the dependency-check database; analysis has stopped");
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, "", ex);
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
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
        Engine engine = null;
        try {
            engine = executeDependencyCheck();
            generateMavenSiteReport(engine, sink);
        } catch (DatabaseException ex) {
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.SEVERE,
                    "Unable to connect to the dependency-check database; analysis has stopped");
            Logger.getLogger(DependencyCheckMojo.class.getName()).log(Level.FINE, "", ex);
        } finally {
            if (engine != null) {
                engine.cleanup();
            }
        }
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
     * Gets the description of the Dependency-Check report to be displayed in the Maven Generated Reports page.
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
     * Checks to see if a vulnerability has been identified with a CVSS score that is above the threshold set in the
     * configuration.
     *
     * @param dependencies the list of dependency objects
     * @throws MojoFailureException thrown if a CVSS score is found that is higher then the threshold set
     */
    private void checkForFailure(List<Dependency> dependencies) throws MojoFailureException {
        final StringBuilder ids = new StringBuilder();
        for (Dependency d : dependencies) {
            boolean addName = true;
            for (Vulnerability v : d.getVulnerabilities()) {
                if (v.getCvssScore() >= failBuildOnCVSS) {
                    if (addName) {
                        addName = false;
                        ids.append(NEW_LINE).append(d.getFileName()).append(": ");
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
     * Generates a warning message listing a summary of dependencies and their associated CPE and CVE entries.
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
