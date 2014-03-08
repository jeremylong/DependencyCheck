/*
 * This file is part of dependency-check-cli.
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
package org.owasp.dependencycheck.cli;

import java.io.File;
import java.io.FileNotFoundException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.owasp.dependencycheck.reporting.ReportGenerator.Format;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 * A utility to parse command line arguments for the DependencyCheck.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class CliParser {

    /**
     * The command line.
     */
    private CommandLine line;
    /**
     * Indicates whether the arguments are valid.
     */
    private boolean isValid = true;

    /**
     * Parses the arguments passed in and captures the results for later use.
     *
     * @param args the command line arguments
     * @throws FileNotFoundException is thrown when a 'file' argument does not point to a file that exists.
     * @throws ParseException is thrown when a Parse Exception occurs.
     */
    public void parse(String[] args) throws FileNotFoundException, ParseException {
        line = parseArgs(args);

        if (line != null) {
            validateArgs();
        }
    }

    /**
     * Parses the command line arguments.
     *
     * @param args the command line arguments
     * @return the results of parsing the command line arguments
     * @throws ParseException if the arguments are invalid
     */
    private CommandLine parseArgs(String[] args) throws ParseException {
        final CommandLineParser parser = new PosixParser();
        final Options options = createCommandLineOptions();
        return parser.parse(options, args);
    }

    /**
     * Validates that the command line arguments are valid.
     *
     * @throws FileNotFoundException if there is a file specified by either the SCAN or CPE command line arguments that
     * does not exist.
     * @throws ParseException is thrown if there is an exception parsing the command line.
     */
    private void validateArgs() throws FileNotFoundException, ParseException {
        if (isRunScan()) {
            validatePathExists(getScanFiles(), ArgumentName.SCAN);
            validatePathExists(getReportDirectory(), ArgumentName.OUT);
            if (getPathToMono() != null) {
                validatePathExists(getPathToMono(), ArgumentName.PATH_TO_MONO);
            }
            if (!line.hasOption(ArgumentName.APP_NAME)) {
                throw new ParseException("Missing 'app' argument; the scan cannot be run without the an application name.");
            }
            if (line.hasOption(ArgumentName.OUTPUT_FORMAT)) {
                final String format = line.getOptionValue(ArgumentName.OUTPUT_FORMAT);
                try {
                    Format.valueOf(format);
                } catch (IllegalArgumentException ex) {
                    final String msg = String.format("An invalid 'format' of '%s' was specified. "
                            + "Supported output formats are XML, HTML, VULN, or ALL", format);
                    throw new ParseException(msg);
                }
            }
        }
    }

    /**
     * Validates whether or not the path(s) points at a file that exists; if the path(s) does not point to an existing
     * file a FileNotFoundException is thrown.
     *
     * @param paths the paths to validate if they exists
     * @param optType the option being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if one of the paths being validated does not exist.
     */
    private void validatePathExists(String[] paths, String optType) throws FileNotFoundException {
        for (String path : paths) {
            validatePathExists(path, optType);
        }
    }

    /**
     * Validates whether or not the path points at a file that exists; if the path does not point to an existing file a
     * FileNotFoundException is thrown.
     *
     * @param path the paths to validate if they exists
     * @param argumentName the argument being validated (e.g. scan, out, etc.)
     * @throws FileNotFoundException is thrown if the path being validated does not exist.
     */
    private void validatePathExists(String path, String argumentName) throws FileNotFoundException {
        final File f = new File(path);
        if (!f.exists()) {
            isValid = false;
            final String msg = String.format("Invalid '%s' argument: '%s'", argumentName, path);
            throw new FileNotFoundException(msg);
        }
    }

    /**
     * Generates an Options collection that is used to parse the command line and to display the help message.
     *
     * @return the command line options used for parsing the command line
     */
    @SuppressWarnings("static-access")
    private Options createCommandLineOptions() {

        final Options options = new Options();
        addStandardOptions(options);
        addAdvancedOptions(options);

        return options;
    }

    /**
     * Adds the standard command line options to the given options collection.
     *
     * @param options a collection of command line arguments
     * @throws IllegalArgumentException thrown if there is an exception
     */
    @SuppressWarnings("static-access")
    private void addStandardOptions(final Options options) throws IllegalArgumentException {
        final Option help = new Option(ArgumentName.HELP_SHORT, ArgumentName.HELP, false,
                "Print this message.");

        final Option advancedHelp = OptionBuilder.withLongOpt(ArgumentName.ADVANCED_HELP)
                .withDescription("Print the advanced help message.").create();

        final Option version = new Option(ArgumentName.VERSION_SHORT, ArgumentName.VERSION,
                false, "Print the version information.");

        final Option noUpdate = new Option(ArgumentName.DISABLE_AUTO_UPDATE_SHORT, ArgumentName.DISABLE_AUTO_UPDATE,
                false, "Disables the automatic updating of the CPE data.");

        final Option appName = OptionBuilder.withArgName("name").hasArg().withLongOpt(ArgumentName.APP_NAME)
                .withDescription("The name of the application being scanned. This is a required argument.")
                .create(ArgumentName.APP_NAME_SHORT);

        final Option path = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.SCAN)
                .withDescription("The path to scan - this option can be specified multiple times.")
                .create(ArgumentName.SCAN_SHORT);

        final Option props = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.PROP)
                .withDescription("A property file to load.")
                .create(ArgumentName.PROP_SHORT);

        final Option out = OptionBuilder.withArgName("folder").hasArg().withLongOpt(ArgumentName.OUT)
                .withDescription("The folder to write reports to. This defaults to the current directory.")
                .create(ArgumentName.OUT_SHORT);

        final Option outputFormat = OptionBuilder.withArgName("format").hasArg().withLongOpt(ArgumentName.OUTPUT_FORMAT)
                .withDescription("The output format to write to (XML, HTML, VULN, ALL). The default is HTML.")
                .create(ArgumentName.OUTPUT_FORMAT_SHORT);

        final Option verboseLog = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.VERBOSE_LOG)
                .withDescription("The file path to write verbose logging information.")
                .create(ArgumentName.VERBOSE_LOG_SHORT);

        final Option suppressionFile = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.SUPPRESION_FILE)
                .withDescription("The file path to the suppression XML file.")
                .create();

        //This is an option group because it can be specified more then once.
        final OptionGroup og = new OptionGroup();
        og.addOption(path);

        options.addOptionGroup(og)
                .addOption(out)
                .addOption(outputFormat)
                .addOption(appName)
                .addOption(version)
                .addOption(help)
                .addOption(advancedHelp)
                .addOption(noUpdate)
                .addOption(props)
                .addOption(verboseLog)
                .addOption(suppressionFile);
    }

    /**
     * Adds the advanced command line options to the given options collection. These are split out for purposes of being
     * able to display two different help messages.
     *
     * @param options a collection of command line arguments
     * @throws IllegalArgumentException thrown if there is an exception
     */
    @SuppressWarnings("static-access")
    private void addAdvancedOptions(final Options options) throws IllegalArgumentException {

        final Option data = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.DATA_DIRECTORY)
                .withDescription("The location of the H2 Database file. This option should generally not be set.")
                .create(ArgumentName.DATA_DIRECTORY_SHORT);

        final Option connectionTimeout = OptionBuilder.withArgName("timeout").hasArg().withLongOpt(ArgumentName.CONNECTION_TIMEOUT)
                .withDescription("The connection timeout (in milliseconds) to use when downloading resources.")
                .create(ArgumentName.CONNECTION_TIMEOUT_SHORT);

        final Option proxyUrl = OptionBuilder.withArgName("url").hasArg().withLongOpt(ArgumentName.PROXY_URL)
                .withDescription("The proxy url to use when downloading resources.")
                .create(ArgumentName.PROXY_URL_SHORT);

        final Option proxyPort = OptionBuilder.withArgName("port").hasArg().withLongOpt(ArgumentName.PROXY_PORT)
                .withDescription("The proxy port to use when downloading resources.")
                .create(ArgumentName.PROXY_PORT_SHORT);

        final Option proxyUsername = OptionBuilder.withArgName("user").hasArg().withLongOpt(ArgumentName.PROXY_USERNAME)
                .withDescription("The proxy username to use when downloading resources.")
                .create();

        final Option proxyPassword = OptionBuilder.withArgName("pass").hasArg().withLongOpt(ArgumentName.PROXY_PASSWORD)
                .withDescription("The proxy password to use when downloading resources.")
                .create();

        final Option connectionString = OptionBuilder.withArgName("connStr").hasArg().withLongOpt(ArgumentName.CONNECTION_STRING)
                .withDescription("The connection string to the database.")
                .create();

        final Option dbUser = OptionBuilder.withArgName("user").hasArg().withLongOpt(ArgumentName.DB_NAME)
                .withDescription("The username used to connect to the database.")
                .create();

        final Option dbPassword = OptionBuilder.withArgName("password").hasArg().withLongOpt(ArgumentName.DB_PASSWORD)
                .withDescription("The password for connecting to the database.")
                .create();

        final Option dbDriver = OptionBuilder.withArgName("driver").hasArg().withLongOpt(ArgumentName.DB_DRIVER)
                .withDescription("The database driver name.")
                .create();

        final Option dbDriverPath = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.DB_DRIVER_PATH)
                .withDescription("The path to the database driver; note, this does not need to be set unless the JAR is outside of the classpath.")
                .create();

        final Option disableNexusAnalyzer = OptionBuilder.withLongOpt(ArgumentName.DISABLE_NEXUS)
                .withDescription("Disable the Nexus Analyzer.")
                .create();

        final Option nexusUrl = OptionBuilder.withArgName("url").hasArg().withLongOpt(ArgumentName.NEXUS_URL)
                .withDescription("The url to the Nexus Server.")
                .create();

        final Option nexusUsesProxy = OptionBuilder.withArgName("true/false").hasArg().withLongOpt(ArgumentName.NEXUS_USES_PROXY)
                .withDescription("Whether or not the configured proxy should be used when connecting to Nexus.")
                .create();

        final Option additionalZipExtensions = OptionBuilder.withArgName("extensions").hasArg()
                .withLongOpt(ArgumentName.ADDITIONAL_ZIP_EXTENSIONS)
                .withDescription("A comma seperated list of additional extensions to be scanned as ZIP files "
                        + "(ZIP, EAR, WAR are already treated as zip files)")
                .create();

        final Option pathToMono = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.PATH_TO_MONO)
                .withDescription("The path to Mono for .NET Assembly analysis on non-windows systems.")
                .create();

        options.addOption(proxyPort)
                .addOption(proxyUrl)
                .addOption(proxyUsername)
                .addOption(proxyPassword)
                .addOption(connectionTimeout)
                .addOption(connectionString)
                .addOption(dbUser)
                .addOption(data)
                .addOption(dbPassword)
                .addOption(dbDriver)
                .addOption(dbDriverPath)
                .addOption(disableNexusAnalyzer)
                .addOption(nexusUrl)
                .addOption(nexusUsesProxy)
                .addOption(additionalZipExtensions)
                .addOption(pathToMono);
    }

    /**
     * Determines if the 'version' command line argument was passed in.
     *
     * @return whether or not the 'version' command line argument was passed in
     */
    public boolean isGetVersion() {
        return (line != null) && line.hasOption(ArgumentName.VERSION);
    }

    /**
     * Determines if the 'help' command line argument was passed in.
     *
     * @return whether or not the 'help' command line argument was passed in
     */
    public boolean isGetHelp() {
        return (line != null) && line.hasOption(ArgumentName.HELP);
    }

    /**
     * Determines if the 'scan' command line argument was passed in.
     *
     * @return whether or not the 'scan' command line argument was passed in
     */
    public boolean isRunScan() {
        return (line != null) && isValid && line.hasOption(ArgumentName.SCAN);
    }

    /**
     * Returns true if the disableNexus command line argument was specified.
     *
     * @return true if the disableNexus command line argument was specified; otherwise false
     */
    public boolean isNexusDisabled() {
        return (line != null) && line.hasOption(ArgumentName.DISABLE_NEXUS);
    }

    /**
     * Returns the url to the nexus server if one was specified.
     *
     * @return the url to the nexus server; if none was specified this will return null;
     */
    public String getNexusUrl() {
        if (line == null || !line.hasOption(ArgumentName.NEXUS_URL)) {
            return null;
        } else {
            return line.getOptionValue(ArgumentName.NEXUS_URL);
        }
    }

    /**
     * Returns true if the Nexus Analyzer should use the configured proxy to connect to Nexus; otherwise false is
     * returned.
     *
     * @return true if the Nexus Analyzer should use the configured proxy to connect to Nexus; otherwise false
     */
    public boolean isNexusUsesProxy() {
        // If they didn't specify whether Nexus needs to use the proxy, we should
        // still honor the property if it's set.
        if (line == null || !line.hasOption(ArgumentName.NEXUS_USES_PROXY)) {
            try {
                return Settings.getBoolean(Settings.KEYS.ANALYZER_NEXUS_PROXY);
            } catch (InvalidSettingException ise) {
                return true;
            }
        } else {
            return Boolean.parseBoolean(line.getOptionValue(ArgumentName.NEXUS_USES_PROXY));
        }
    }

    /**
     * Displays the command line help message to the standard output.
     */
    public void printHelp() {
        final HelpFormatter formatter = new HelpFormatter();
        final Options options = new Options();
        addStandardOptions(options);
        if (line != null && line.hasOption(ArgumentName.ADVANCED_HELP)) {
            addAdvancedOptions(options);
        }
        final String helpMsg = String.format("%n%s"
                + " can be used to identify if there are any known CVE vulnerabilities in libraries utilized by an application. "
                + "%s will automatically update required data from the Internet, such as the CVE and CPE data files from nvd.nist.gov.%n%n",
                Settings.getString("application.name", "DependencyCheck"),
                Settings.getString("application.name", "DependencyCheck"));

        formatter.printHelp(Settings.getString("application.name", "DependencyCheck"),
                helpMsg,
                options,
                "",
                true);

    }

    /**
     * Retrieves the file command line parameter(s) specified for the 'scan' argument.
     *
     * @return the file paths specified on the command line for scan
     */
    public String[] getScanFiles() {
        return line.getOptionValues(ArgumentName.SCAN);
    }

    /**
     * Returns the directory to write the reports to specified on the command line.
     *
     * @return the path to the reports directory.
     */
    public String getReportDirectory() {
        return line.getOptionValue(ArgumentName.OUT, ".");
    }

    /**
     * Returns the path to Mono for .NET Assembly analysis on non-windows systems.
     *
     * @return the path to Mono
     */
    public String getPathToMono() {
        return line.getOptionValue(ArgumentName.PATH_TO_MONO);
    }

    /**
     * Returns the output format specified on the command line. Defaults to HTML if no format was specified.
     *
     * @return the output format name.
     */
    public String getReportFormat() {
        return line.getOptionValue(ArgumentName.OUTPUT_FORMAT, "HTML");
    }

    /**
     * Returns the application name specified on the command line.
     *
     * @return the application name.
     */
    public String getApplicationName() {
        return line.getOptionValue(ArgumentName.APP_NAME);
    }

    /**
     * Returns the connection timeout.
     *
     * @return the connection timeout
     */
    public String getConnectionTimeout() {
        return line.getOptionValue(ArgumentName.CONNECTION_TIMEOUT);
    }

    /**
     * Returns the proxy url.
     *
     * @return the proxy url
     */
    public String getProxyUrl() {
        return line.getOptionValue(ArgumentName.PROXY_URL);
    }

    /**
     * Returns the proxy port.
     *
     * @return the proxy port
     */
    public String getProxyPort() {
        return line.getOptionValue(ArgumentName.PROXY_PORT);
    }

    /**
     * Returns the proxy username.
     *
     * @return the proxy username
     */
    public String getProxyUsername() {
        return line.getOptionValue(ArgumentName.PROXY_USERNAME);
    }

    /**
     * Returns the proxy password.
     *
     * @return the proxy password
     */
    public String getProxyPassword() {
        return line.getOptionValue(ArgumentName.PROXY_PASSWORD);
    }

    /**
     * Get the value of dataDirectory.
     *
     * @return the value of dataDirectory
     */
    public String getDataDirectory() {
        return line.getOptionValue(ArgumentName.DATA_DIRECTORY);
    }

    /**
     * Returns the properties file specified on the command line.
     *
     * @return the properties file specified on the command line
     */
    public File getPropertiesFile() {
        final String path = line.getOptionValue(ArgumentName.PROP);
        if (path != null) {
            return new File(path);
        }
        return null;
    }

    /**
     * Returns the path to the verbose log file.
     *
     * @return the path to the verbose log file
     */
    public String getVerboseLog() {
        return line.getOptionValue(ArgumentName.VERBOSE_LOG);
    }

    /**
     * Returns the path to the suppression file.
     *
     * @return the path to the suppression file
     */
    public String getSuppressionFile() {
        return line.getOptionValue(ArgumentName.SUPPRESION_FILE);
    }

    /**
     * <p>
     * Prints the manifest information to standard output.</p>
     * <ul><li>Implementation-Title: ${pom.name}</li>
     * <li>Implementation-Version: ${pom.version}</li></ul>
     */
    public void printVersionInfo() {
        final String version = String.format("%s version %s",
                Settings.getString("application.name", "DependencyCheck"),
                Settings.getString("application.version", "Unknown"));
        System.out.println(version);
    }

    /**
     * Checks if the auto update feature has been disabled. If it has been disabled via the command line this will
     * return false.
     *
     * @return if auto-update is allowed.
     */
    public boolean isAutoUpdate() {
        return (line == null) || !line.hasOption(ArgumentName.DISABLE_AUTO_UPDATE);
    }

    /**
     * Returns the database driver name if specified; otherwise null is returned.
     *
     * @return the database driver name if specified; otherwise null is returned
     */
    public String getDatabaseDriverName() {
        return line.getOptionValue(ArgumentName.DB_DRIVER);
    }

    /**
     * Returns the database driver path if specified; otherwise null is returned.
     *
     * @return the database driver name if specified; otherwise null is returned
     */
    public String getDatabaseDriverPath() {
        return line.getOptionValue(ArgumentName.DB_DRIVER_PATH);
    }

    /**
     * Returns the database connection string if specified; otherwise null is returned.
     *
     * @return the database connection string if specified; otherwise null is returned
     */
    public String getConnectionString() {
        return line.getOptionValue(ArgumentName.CONNECTION_STRING);
    }

    /**
     * Returns the database database user name if specified; otherwise null is returned.
     *
     * @return the database database user name if specified; otherwise null is returned
     */
    public String getDatabaseUser() {
        return line.getOptionValue(ArgumentName.DB_NAME);
    }

    /**
     * Returns the database database password if specified; otherwise null is returned.
     *
     * @return the database database password if specified; otherwise null is returned
     */
    public String getDatabasePassword() {
        return line.getOptionValue(ArgumentName.DB_PASSWORD);
    }

    /**
     * Returns the additional Extensions if specified; otherwise null is returned.
     *
     * @return the additional Extensions; otherwise null is returned
     */
    public String getAdditionalZipExtensions() {
        return line.getOptionValue(ArgumentName.ADDITIONAL_ZIP_EXTENSIONS);
    }

    /**
     * A collection of static final strings that represent the possible command line arguments.
     */
    public static class ArgumentName {

        /**
         * The long CLI argument name specifying the directory/file to scan.
         */
        public static final String SCAN = "scan";
        /**
         * The short CLI argument name specifying the directory/file to scan.
         */
        public static final String SCAN_SHORT = "s";
        /**
         * The long CLI argument name specifying that the CPE/CVE/etc. data should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE = "noupdate";
        /**
         * The short CLI argument name specifying that the CPE/CVE/etc. data should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE_SHORT = "n";
        /**
         * The long CLI argument name specifying the directory to write the reports to.
         */
        public static final String OUT = "out";
        /**
         * The short CLI argument name specifying the directory to write the reports to.
         */
        public static final String OUT_SHORT = "o";
        /**
         * The long CLI argument name specifying the output format to write the reports to.
         */
        public static final String OUTPUT_FORMAT = "format";
        /**
         * The short CLI argument name specifying the output format to write the reports to.
         */
        public static final String OUTPUT_FORMAT_SHORT = "f";
        /**
         * The long CLI argument name specifying the name of the application to be scanned.
         */
        public static final String APP_NAME = "app";
        /**
         * The short CLI argument name specifying the name of the application to be scanned.
         */
        public static final String APP_NAME_SHORT = "a";
        /**
         * The long CLI argument name asking for help.
         */
        public static final String HELP = "help";
        /**
         * The long CLI argument name asking for advanced help.
         */
        public static final String ADVANCED_HELP = "advancedHelp";
        /**
         * The short CLI argument name asking for help.
         */
        public static final String HELP_SHORT = "h";
        /**
         * The long CLI argument name asking for the version.
         */
        public static final String VERSION_SHORT = "v";
        /**
         * The short CLI argument name asking for the version.
         */
        public static final String VERSION = "version";
        /**
         * The short CLI argument name indicating the proxy port.
         */
        public static final String PROXY_PORT_SHORT = "p";
        /**
         * The CLI argument name indicating the proxy port.
         */
        public static final String PROXY_PORT = "proxyport";
        /**
         * The short CLI argument name indicating the proxy url.
         */
        public static final String PROXY_URL_SHORT = "u";
        /**
         * The CLI argument name indicating the proxy url.
         */
        public static final String PROXY_URL = "proxyurl";
        /**
         * The CLI argument name indicating the proxy username.
         */
        public static final String PROXY_USERNAME = "proxyuser";
        /**
         * The CLI argument name indicating the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxypass";
        /**
         * The short CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT_SHORT = "c";
        /**
         * The CLI argument name indicating the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connectiontimeout";
        /**
         * The short CLI argument name for setting the location of an additional properties file.
         */
        public static final String PROP_SHORT = "P";
        /**
         * The CLI argument name for setting the location of an additional properties file.
         */
        public static final String PROP = "propertyfile";
        /**
         * The CLI argument name for setting the location of the data directory.
         */
        public static final String DATA_DIRECTORY = "data";
        /**
         * The short CLI argument name for setting the location of the data directory.
         */
        public static final String DATA_DIRECTORY_SHORT = "d";
        /**
         * The CLI argument name for setting the location of the data directory.
         */
        public static final String VERBOSE_LOG = "log";
        /**
         * The short CLI argument name for setting the location of the data directory.
         */
        public static final String VERBOSE_LOG_SHORT = "l";
        /**
         * The CLI argument name for setting the location of the suppression file.
         */
        public static final String SUPPRESION_FILE = "suppression";
        /**
         * Disables the Nexus Analyzer.
         */
        public static final String DISABLE_NEXUS = "disableNexus";
        /**
         * The URL of the nexus server.
         */
        public static final String NEXUS_URL = "nexus";
        /**
         * Whether or not the defined proxy should be used when connecting to Nexus.
         */
        public static final String NEXUS_USES_PROXY = "nexusUsesProxy";
        /**
         * The CLI argument name for setting the connection string.
         */
        public static final String CONNECTION_STRING = "connectionString";
        /**
         * The CLI argument name for setting the database user name.
         */
        public static final String DB_NAME = "dbUser";
        /**
         * The CLI argument name for setting the database password.
         */
        public static final String DB_PASSWORD = "dbPassword";
        /**
         * The CLI argument name for setting the database driver name.
         */
        public static final String DB_DRIVER = "dbDriverName";
        /**
         * The CLI argument name for setting the path to the database driver; in case it is not on the class path.
         */
        public static final String DB_DRIVER_PATH = "dbDriverPath";
        /**
         * The CLI argument name for setting the path to mono for .NET Assembly analysis on non-windows systems.
         */
        public static final String PATH_TO_MONO = "mono";
        /**
         * The CLI argument name for setting extra extensions.
         */
        public static final String ADDITIONAL_ZIP_EXTENSIONS = "zipExtensions";
    }
}
