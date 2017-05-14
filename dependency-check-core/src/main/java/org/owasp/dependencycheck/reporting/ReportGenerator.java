/*
 * This file is part of dependency-check-core.
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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.io.*;
import java.util.List;

import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import static com.google.gson.stream.JsonToken.*;
import com.google.gson.stream.JsonWriter;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.context.Context;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.owasp.dependencycheck.analyzer.Analyzer;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The ReportGenerator is used to, as the name implies, generate reports.
 * Internally the generator uses the Velocity Templating Engine. The
 * ReportGenerator exposes a list of Dependencies to the template when
 * generating the report.
 *
 * @author Jeremy Long
 */
public class ReportGenerator {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ReportGenerator.class);

    /**
     * An enumeration of the report formats.
     */
    public enum Format {

        /**
         * Generate all reports.
         */
        ALL,
        /**
         * Generate XML report.
         */
        XML,
        /**
         * Generate HTML report.
         */
        HTML,
        /**
         * Generate HTML Vulnerability report.
         */
        VULN,
        /**
         * Generate JSON report.
         */
        JSON,
        /**
         * Generate CSV report.
         */
        CSV
    }
    /**
     * The Velocity Engine.
     */
    private final VelocityEngine velocityEngine;
    /**
     * The Velocity Engine Context.
     */
    private final Context context;

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     */
    public ReportGenerator(String applicationName, List<Dependency> dependencies, List<Analyzer> analyzers, DatabaseProperties properties) {
        velocityEngine = createVelocityEngine();
        context = createContext();

        velocityEngine.init();
        final EscapeTool enc = new EscapeTool();

        final DateTime dt = new DateTime();
        final DateTimeFormatter dateFormat = DateTimeFormat.forPattern("MMM d, yyyy 'at' HH:mm:ss z");
        final DateTimeFormatter dateFormatXML = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

//        final Date d = new Date();
//        final DateFormat dateFormat = new SimpleDateFormat("MMM d, yyyy 'at' HH:mm:ss z");
//        final DateFormat dateFormatXML = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        final String scanDate = dateFormat.print(dt);
        final String scanDateXML = dateFormatXML.print(dt);

        context.put("applicationName", applicationName);
        context.put("dependencies", dependencies);
        context.put("analyzers", analyzers);
        context.put("properties", properties);
        context.put("scanDate", scanDate);
        context.put("scanDateXML", scanDateXML);
        context.put("enc", enc);
        context.put("version", Settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown"));
    }

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param groupID the group id of the project being analyzed
     * @param artifactID the application id of the project being analyzed
     * @param version the application version of the project being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     */
    public ReportGenerator(String applicationName, String groupID, String artifactID, String version,
            List<Dependency> dependencies, List<Analyzer> analyzers, DatabaseProperties properties) {

        this(applicationName, dependencies, analyzers, properties);
        context.put("applicationVersion", version);
        context.put("artifactID", artifactID);
        context.put("groupID", groupID);
    }

    /**
     * Creates a new Velocity Engine.
     *
     * @return a velocity engine
     */
    private VelocityEngine createVelocityEngine() {
        final VelocityEngine velocity = new VelocityEngine();
        // Logging redirection for Velocity - Required by Jenkins and other server applications
        velocity.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, VelocityLoggerRedirect.class.getName());
        return velocity;
    }

    /**
     * Creates a new Velocity Context.
     *
     * @return a Velocity Context
     */
    private Context createContext() {
        return new VelocityContext();
    }

    /**
     * Generates the Dependency Reports for the identified dependencies.
     *
     * @param outputStream the OutputStream to send the generated report to
     * @param format the format the report should be written in
     * @throws IOException is thrown when the template file does not exist
     * @throws Exception is thrown if there is an error writing out the reports
     */
    public void generateReports(OutputStream outputStream, Format format) throws IOException, Exception {
        if (format == Format.XML || format == Format.ALL) {
            generateReport("XmlReport", outputStream);
        }
        if (format == Format.HTML || format == Format.ALL) {
            generateReport("HtmlReport", outputStream);
        }
        if (format == Format.VULN || format == Format.ALL) {
            generateReport("VulnerabilityReport", outputStream);
        }
        if (format == Format.JSON || format == Format.ALL) {
            generateReport("JsonReport", outputStream);
        }
        if (format == Format.CSV || format == Format.ALL) {
            generateReport("CsvReport", outputStream);
        }
    }

    /**
     * Generates the Dependency Reports for the identified dependencies.
     *
     * @param outputDir the path where the reports should be written
     * @param format the format the report should be written in
     * @throws ReportException is thrown if there is an error writing out the
     * reports
     */
    public void generateReports(String outputDir, Format format) throws ReportException {
        if (format == Format.XML || format == Format.ALL) {
            generateReport("XmlReport", outputDir + File.separator + "dependency-check-report.xml");
        }
        if (format == Format.JSON || format == Format.ALL) {
            generateReport("JsonReport", outputDir + File.separator + "dependency-check-report.json");
            pretifyJson(outputDir + File.separator + "dependency-check-report.json");
        }
        if (format == Format.CSV || format == Format.ALL) {
            generateReport("CsvReport", outputDir + File.separator + "dependency-check-report.csv");
        }
        if (format == Format.HTML || format == Format.ALL) {
            generateReport("HtmlReport", outputDir + File.separator + "dependency-check-report.html");
        }
        if (format == Format.VULN || format == Format.ALL) {
            generateReport("VulnerabilityReport", outputDir + File.separator + "dependency-check-vulnerability.html");
        }
    }

    /**
     * Reformats the given JSON file.
     *
     * @param pathToJson the path to the JSON file to be reformatted
     * @throws JsonSyntaxException thrown if the given JSON file is malformed
     */
    private void pretifyJson(String pathToJson) throws JsonSyntaxException {
        final String outputPath = pathToJson + ".pretty";
        final File in = new File(pathToJson);
        final File out = new File(outputPath);
        try (JsonReader reader = new JsonReader(new InputStreamReader(new FileInputStream(in), StandardCharsets.UTF_8));
                JsonWriter writer = new JsonWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
            prettyPrint(reader, writer);
        } catch (IOException ex) {
            LOGGER.error("Unable to generate pretty report, caused by: ", ex.getMessage());
            return;
        }
        if (out.isFile() && in.isFile() && in.delete()) {
            try {
                org.apache.commons.io.FileUtils.moveFile(out, in);
            } catch (IOException ex) {
                LOGGER.error("Unable to generate pretty report, caused by: ", ex.getMessage());
            }
        }
    }

    /**
     * Streams from a json reader to a json writer and performs pretty printing.
     *
     * This function is copied from https://sites.google.com/site/gson/streaming
     *
     * @param reader json reader
     * @param writer json writer
     * @throws IOException thrown if the json is malformed
     */
    private static void prettyPrint(JsonReader reader, JsonWriter writer) throws IOException {
        writer.setIndent("  ");
        while (true) {
            final JsonToken token = reader.peek();
            switch (token) {
                case BEGIN_ARRAY:
                    reader.beginArray();
                    writer.beginArray();
                    break;
                case END_ARRAY:
                    reader.endArray();
                    writer.endArray();
                    break;
                case BEGIN_OBJECT:
                    reader.beginObject();
                    writer.beginObject();
                    break;
                case END_OBJECT:
                    reader.endObject();
                    writer.endObject();
                    break;
                case NAME:
                    final String name = reader.nextName();
                    writer.name(name);
                    break;
                case STRING:
                    final String s = reader.nextString();
                    writer.value(s);
                    break;
                case NUMBER:
                    final String n = reader.nextString();
                    writer.value(new BigDecimal(n));
                    break;
                case BOOLEAN:
                    final boolean b = reader.nextBoolean();
                    writer.value(b);
                    break;
                case NULL:
                    reader.nextNull();
                    writer.nullValue();
                    break;
                case END_DOCUMENT:
                    return;
                default:
                    LOGGER.debug("Unexpected JSON toekn {}", token.toString());
                    break;
            }
        }
    }

    /**
     * Generates the Dependency Reports for the identified dependencies.
     *
     * @param outputDir the path where the reports should be written
     * @param outputFormat the format the report should be written in (XML,
     * HTML, ALL)
     * @throws ReportException is thrown if there is an error creating out the
     * reports
     */
    public void generateReports(String outputDir, String outputFormat) throws ReportException {
        final String format = outputFormat.toUpperCase();
        final String pathToCheck = outputDir.toLowerCase();
        if (format.matches("^(XML|HTML|VULN|JSON|ALL)$")) {
            if ("XML".equalsIgnoreCase(format)) {
                if (pathToCheck.endsWith(".xml")) {
                    generateReport("XmlReport", outputDir);
                } else {
                    generateReports(outputDir, Format.XML);
                }
            }
            if ("HTML".equalsIgnoreCase(format)) {
                if (pathToCheck.endsWith(".html") || pathToCheck.endsWith(".htm")) {
                    generateReport("HtmlReport", outputDir);
                } else {
                    generateReports(outputDir, Format.HTML);
                }
            }
            if ("VULN".equalsIgnoreCase(format)) {
                if (pathToCheck.endsWith(".html") || pathToCheck.endsWith(".htm")) {
                    generateReport("VulnReport", outputDir);
                } else {
                    generateReports(outputDir, Format.VULN);
                }
            }
            if ("JSON".equalsIgnoreCase(format)) {
                if (pathToCheck.endsWith(".json")) {
                    generateReport("JsonReport", outputDir);
                    pretifyJson(outputDir);
                } else {
                    generateReports(outputDir, Format.JSON);
                }
            }
            if ("CSV".equalsIgnoreCase(format)) {
                if (pathToCheck.endsWith(".csv")) {
                    generateReport("CsvReport", outputDir);
                } else {
                    generateReports(outputDir, Format.JSON);
                }
            }
            if ("ALL".equalsIgnoreCase(format)) {
                generateReports(outputDir, Format.ALL);
            }
        }
    }

    /**
     * Generates a report from a given Velocity Template. The template name
     * provided can be the name of a template contained in the jar file, such as
     * 'XmlReport' or 'HtmlReport', or the template name can be the path to a
     * template file.
     *
     * @param templateName the name of the template to load
     * @param outputStream the OutputStream to write the report to
     * @throws ReportException is thrown when an exception occurs
     */
    protected void generateReport(String templateName, OutputStream outputStream) throws ReportException {
        InputStream input = null;
        String templatePath = null;
        final File f = new File(templateName);
        try {
            if (f.exists() && f.isFile()) {
                try {
                    templatePath = templateName;
                    input = new FileInputStream(f);
                } catch (FileNotFoundException ex) {
                    throw new ReportException("Unable to locate template file: " + templateName, ex);
                }
            } else {
                templatePath = "templates/" + templateName + ".vsl";
                input = this.getClass().getClassLoader().getResourceAsStream(templatePath);
            }
            if (input == null) {
                throw new ReportException("Template file doesn't exist: " + templatePath);
            }

            try (InputStreamReader reader = new InputStreamReader(input, "UTF-8");
                    OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8")) {
                if (!velocityEngine.evaluate(context, writer, templatePath, reader)) {
                    throw new ReportException("Failed to convert the template into html.");
                }
                writer.flush();
            } catch (UnsupportedEncodingException ex) {
                throw new ReportException("Unable to generate the report using UTF-8", ex);
            } catch (IOException ex) {
                throw new ReportException("Unable to write the report", ex);
            }
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException ex) {
                    LOGGER.trace("Error closing input", ex);
                }
            }
        }
    }

    /**
     * Generates a report from a given Velocity Template. The template name
     * provided can be the name of a template contained in the jar file, such as
     * 'XmlReport' or 'HtmlReport', or the template name can be the path to a
     * template file.
     *
     * @param templateName the name of the template to load
     * @param outFileName the filename and path to write the report to
     * @throws ReportException is thrown when the report cannot be generated
     */
    protected void generateReport(String templateName, String outFileName) throws ReportException {
        File outFile = new File(outFileName);
        if (outFile.getParentFile() == null) {
            outFile = new File(".", outFileName);
        }
        if (!outFile.getParentFile().exists()) {
            final boolean created = outFile.getParentFile().mkdirs();
            if (!created) {
                throw new ReportException("Unable to create directory '" + outFile.getParentFile().getAbsolutePath() + "'.");
            }
        }
        try (OutputStream outputSteam = new FileOutputStream(outFile)) {
            generateReport(templateName, outputSteam);
        } catch (IOException ex) {
            throw new ReportException("Unable to write to file: " + outFile, ex);
        }
    }
}
