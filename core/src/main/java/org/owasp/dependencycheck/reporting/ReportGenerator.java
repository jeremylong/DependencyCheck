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

import java.util.List;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import javax.annotation.concurrent.NotThreadSafe;
import org.apache.commons.text.WordUtils;
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
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.FileUtils;
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
@NotThreadSafe
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
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Constructs a new ReportGenerator.
     *
     * @param applicationName the application name being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @param settings a reference to the database settings
     */
    public ReportGenerator(String applicationName, List<Dependency> dependencies, List<Analyzer> analyzers,
            DatabaseProperties properties, Settings settings) {
        this.settings = settings;
        velocityEngine = createVelocityEngine();
        velocityEngine.init();
        context = createContext(applicationName, dependencies, analyzers, properties);
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
     * @param settings a reference to the database settings
     */
    //CSOFF: ParameterNumber
    public ReportGenerator(String applicationName, String groupID, String artifactID, String version,
            List<Dependency> dependencies, List<Analyzer> analyzers, DatabaseProperties properties, Settings settings) {
        this(applicationName, dependencies, analyzers, properties, settings);
        if (version != null) {
            context.put("applicationVersion", version);
        }
        if (artifactID != null) {
            context.put("artifactID", artifactID);
        }
        if (groupID != null) {
            context.put("groupID", groupID);
        }
    }
    //CSON: ParameterNumber

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
     * Constructs the velocity context used to generate the dependency-check
     * reports.
     *
     * @param applicationName the application name being analyzed
     * @param dependencies the list of dependencies
     * @param analyzers the list of analyzers used
     * @param properties the database properties (containing timestamps of the
     * NVD CVE data)
     * @return the velocity context
     */
    private VelocityContext createContext(String applicationName, List<Dependency> dependencies,
            List<Analyzer> analyzers, DatabaseProperties properties) {
        final DateTime dt = new DateTime();
        final DateTimeFormatter dateFormat = DateTimeFormat.forPattern("MMM d, yyyy 'at' HH:mm:ss z");
        final DateTimeFormatter dateFormatXML = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

        final String scanDate = dateFormat.print(dt);
        final String scanDateXML = dateFormatXML.print(dt);

        final VelocityContext ctxt = new VelocityContext();
        ctxt.put("applicationName", applicationName);
        ctxt.put("dependencies", dependencies);
        ctxt.put("analyzers", analyzers);
        ctxt.put("properties", properties);
        ctxt.put("scanDate", scanDate);
        ctxt.put("scanDateXML", scanDateXML);
        ctxt.put("enc", new EscapeTool());
        ctxt.put("WordUtils", new WordUtils());
        ctxt.put("VENDOR", EvidenceType.VENDOR);
        ctxt.put("PRODUCT", EvidenceType.PRODUCT);
        ctxt.put("VERSION", EvidenceType.VERSION);
        ctxt.put("version", settings.getString(Settings.KEYS.APPLICATION_VERSION, "Unknown"));
        return ctxt;
    }

    /**
     * Writes the dependency-check report to the given output location.
     *
     * @param outputLocation the path where the reports should be written
     * @param format the format the report should be written in (XML, HTML,
     * JSON, CSV, ALL) or even the path to a custom velocity template (either
     * fully qualified or the template name on the class path).
     * @throws ReportException is thrown if there is an error creating out the
     * reports
     */
    public void write(String outputLocation, String format) throws ReportException {
        Format reportFormat = null;
        try {
            reportFormat = Format.valueOf(format.toUpperCase());
        } catch (IllegalArgumentException ex) {
            LOGGER.trace("ignore this exception", ex);
        }

        if (reportFormat != null) {
            write(outputLocation, reportFormat);
        } else {
            final File out = getReportFile(outputLocation, null);
            if (out.isDirectory()) {
                throw new ReportException("Unable to write non-standard VSL output to a directory, please specify a file name");
            }
            processTemplate(format, out);
        }

    }

    /**
     * Writes the dependency-check report(s).
     *
     * @param outputLocation the path where the reports should be written
     * @param format the format the report should be written in (XML, HTML, ALL)
     * @throws ReportException is thrown if there is an error creating out the
     * reports
     */
    public void write(String outputLocation, Format format) throws ReportException {
        if (format == Format.ALL) {
            for (Format f : Format.values()) {
                if (f != Format.ALL) {
                    write(outputLocation, f);
                }
            }
        } else {
            final File out = getReportFile(outputLocation, format);
            final String templateName = format.toString().toLowerCase() + "Report";
            processTemplate(templateName, out);
            if (format == Format.JSON) {
                pretifyJson(out.getPath());
            }
        }
    }

    /**
     * Determines the report file name based on the give output location and
     * format. If the output location contains a full file name that has the
     * correct extension for the given report type then the output location is
     * returned. However, if the output location is a directory, this method
     * will generate the correct name for the given output format.
     *
     * @param outputLocation the specified output location
     * @param format the report format
     * @return the report File
     */
    protected File getReportFile(String outputLocation, Format format) {
        File outFile = new File(outputLocation);
        if (outFile.getParentFile() == null) {
            outFile = new File(".", outputLocation);
        }
        final String pathToCheck = outputLocation.toLowerCase();
        if (format == Format.XML && !pathToCheck.endsWith(".xml")) {
            return new File(outFile, "dependency-check-report.xml");
        }
        if (format == Format.HTML && !pathToCheck.endsWith(".html") && !pathToCheck.endsWith(".htm")) {
            return new File(outFile, "dependency-check-report.html");
        }
        if (format == Format.VULN && !pathToCheck.endsWith(".html") && !pathToCheck.endsWith(".htm")) {
            return new File(outFile, "dependency-check-vulnerability.html");
        }
        if (format == Format.JSON && !pathToCheck.endsWith(".json")) {
            return new File(outFile, "dependency-check-report.json");
        }
        if (format == Format.CSV && !pathToCheck.endsWith(".csv")) {
            return new File(outFile, "dependency-check-report.csv");
        }
        return outFile;
    }

    /**
     * Generates a report from a given Velocity Template. The template name
     * provided can be the name of a template contained in the jar file, such as
     * 'XmlReport' or 'HtmlReport', or the template name can be the path to a
     * template file.
     *
     * @param template the name of the template to load
     * @param file the output file to write the report to
     * @throws ReportException is thrown when the report cannot be generated
     */
    protected void processTemplate(String template, File file) throws ReportException {
        ensureParentDirectoryExists(file);
        try (OutputStream output = new FileOutputStream(file)) {
            processTemplate(template, output);
        } catch (IOException ex) {
            throw new ReportException(String.format("Unable to write to file: %s", file), ex);
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
    protected void processTemplate(String templateName, OutputStream outputStream) throws ReportException {
        InputStream input = null;
        String logTag = null;
        final File f = new File(templateName);
        try {
            if (f.isFile()) {
                try {
                    logTag = templateName;
                    input = new FileInputStream(f);
                } catch (FileNotFoundException ex) {
                    throw new ReportException("Unable to locate template file: " + templateName, ex);
                }
            } else {
                logTag = "templates/" + templateName + ".vsl";
                input = FileUtils.getResourceAsStream(logTag);
            }
            if (input == null) {
                logTag = templateName;
                input = FileUtils.getResourceAsStream(templateName);
            }
            if (input == null) {
                throw new ReportException("Template file doesn't exist: " + logTag);
            }

            try (InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8);
                    OutputStreamWriter writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8)) {
                if (!velocityEngine.evaluate(context, writer, logTag, reader)) {
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
     * Validates that the given file's parent directory exists. If the directory
     * does not exist an attempt to create the necessary path is made; if that
     * fails a ReportException will be raised.
     *
     * @param file the file or directory directory
     * @throws ReportException thrown if the parent directory does not exist and
     * cannot be created
     */
    private void ensureParentDirectoryExists(File file) throws ReportException {
        if (!file.getParentFile().exists()) {
            final boolean created = file.getParentFile().mkdirs();
            if (!created) {
                final String msg = String.format("Unable to create directory '%s'.", file.getParentFile().getAbsolutePath());
                throw new ReportException(msg);
            }
        }
    }

    /**
     * Reformats the given JSON file.
     *
     * @param pathToJson the path to the JSON file to be reformatted
     * @throws ReportException thrown if the given JSON file is malformed
     */
    private void pretifyJson(String pathToJson) throws ReportException {
        final String outputPath = pathToJson + ".pretty";
        final File in = new File(pathToJson);
        final File out = new File(outputPath);
        try (JsonReader reader = new JsonReader(new InputStreamReader(new FileInputStream(in), StandardCharsets.UTF_8));
                JsonWriter writer = new JsonWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
            prettyPrint(reader, writer);
        } catch (IOException ex) {
            LOGGER.debug("Malformed JSON?", ex);
            throw new ReportException("Unable to generate json report", ex);
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
}
