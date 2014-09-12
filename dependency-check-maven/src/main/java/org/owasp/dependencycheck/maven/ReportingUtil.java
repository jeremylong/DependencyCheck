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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.maven.doxia.sink.Sink;
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

/**
 * A utility class that encapsulates the report generation for dependency-check-maven.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
final class ReportingUtil {

    /**
     * Logger field reference.
     */
    private static final Logger LOGGER = Logger.getLogger(ReportingUtil.class.getName());

    /**
     * Empty private constructor for this utility class.
     */
    private ReportingUtil() {
    }

    /**
     * Generates the reports for a given dependency-check engine.
     *
     * @param engine a dependency-check engine
     * @param outDirectory the directory to write the reports to
     * @param projectName the name of the project that a report is being generated for
     * @param format the format of the report to generate
     */
    static void generateExternalReports(Engine engine, File outDirectory, String projectName, String format) {
        DatabaseProperties prop = null;
        CveDB cve = null;
        try {
            cve = new CveDB();
            cve.open();
            prop = cve.getDatabaseProperties();
        } catch (DatabaseException ex) {
            LOGGER.log(Level.FINE, "Unable to retrieve DB Properties", ex);
        } finally {
            if (cve != null) {
                cve.close();
            }
        }
        final ReportGenerator r = new ReportGenerator(projectName, engine.getDependencies(), engine.getAnalyzers(), prop);
        try {
            r.generateReports(outDirectory.getCanonicalPath(), format);
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE,
                    "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            LOGGER.log(Level.FINE, null, ex);
        } catch (Throwable ex) {
            LOGGER.log(Level.SEVERE,
                    "Unexpected exception occurred during analysis; please see the verbose error log for more details.");
            LOGGER.log(Level.FINE, null, ex);
        }
    }

    /**
     * Generates a dependency-check report using the Maven Site format.
     *
     * @param engine the engine used to scan the dependencies
     * @param sink the sink to write the data to
     * @param projectName the name of the project
     */
    static void generateMavenSiteReport(final Engine engine, Sink sink, String projectName) {
        final List<Dependency> dependencies = engine.getDependencies();

        writeSiteReportHeader(sink, projectName);
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
    private static void writeSiteReportDependencyVulnerabilities(Dependency d, Sink sink, int collapsibleHeaderCount) {
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
    private static void writeSiteReportDependencyIdentifiers(Dependency d, Sink sink) {
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
    private static int writeSiteReportDependencyRelatedDependencies(Dependency d, int collapsibleHeaderCount, Sink sink) {
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
    private static int writeSiteReportDependencyEvidenceUsed(Dependency d, int collapsibleHeaderCount, Sink sink) {
        int cnt = collapsibleHeaderCount;
        final Set<Evidence> evidence = d.getEvidenceForDisplay();
        if (evidence != null && evidence.size() > 0) {
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
            for (Evidence e : evidence) {
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
    private static void writeSiteReportDependencyHeader(Sink sink, Dependency d) {
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
    private static void writeListItem(Sink sink, String text) {
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
    private static void writeTableCell(Sink sink, String text) {
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
    private static void writeTableHeaderCell(Sink sink, String text) {
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
    private static void writeSiteReportTOC(Sink sink, final List<Dependency> dependencies) {
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
    private static void writeSiteReportHeader(Sink sink, String projectName) {
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

}
