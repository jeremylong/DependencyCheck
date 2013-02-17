/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.codesecure.dependencycheck.utils;

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

/**
 * A utility to parse command line arguments for the DependencyCheck.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class CliParser {

    /**
     * The command line.
     */
    private CommandLine line = null;
    /**
     * The options for the command line parser.
     */
    private Options options = createCommandLineOptions();
    /**
     * indicates whether the arguments are valid.
     */
    boolean isValid = true;

    /**
     * Parses the arguments passed in and captures the results for later use.
     *
     * @param args the command line arguments
     * @throws FileNotFoundException is thrown when a 'file' argument does not
     * point to a file that exists.
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
        CommandLineParser parser = new PosixParser();
        CommandLine ln = parser.parse(options, args);
        return ln;
    }

    /**
     * Validates that the command line arguments are valid.
     *
     * @throws FileNotFoundException if there is a file specified by either the
     * SCAN or CPE command line arguments that does not exist.
     */
    private void validateArgs() throws FileNotFoundException, ParseException {
        if (isRunScan()) {
            validatePathExists(getScanFiles());
            if (!line.hasOption(ArgumentName.OUT)) {
                //TODO - need a new exception type here, this isn't really a parseexception.
                throw new ParseException("Scan cannot be run without specifying a directory "
                        + "to write the reports to via the 'out' argument.");
            } else {
                String p = line.getOptionValue(ArgumentName.OUT, "");
                File f = new File(p);
                if ("".equals(p) || !(f.exists() && f.isDirectory())) {
                    //TODO - need a new exception type here, this isn't really a parseexception.
                    throw new ParseException("A valid directory name must be specified for "
                            + "the 'out' argument.");
                }
            }
            if (!line.hasOption(ArgumentName.APPNAME)) {
                throw new ParseException("Scan cannot be run without specifying an application "
                        + "name via the 'app' argument.");
            }
            if (line.hasOption(ArgumentName.OUTPUT_FORMAT)) {
                String format = line.getOptionValue(ArgumentName.OUTPUT_FORMAT);
                if (!(format.equalsIgnoreCase("XML") || format.equalsIgnoreCase("HTML")))
                    throw new ParseException("Supported output formats are XML and HTML");
            }
        }
    }

    /**
     * Validates whether or not the path(s) points at a file that exists; if the
     * path(s) does not point to an existing file a FileNotFoundException is
     * thrown.
     *
     * @param paths the paths to validate if they exists
     * @throws FileNotFoundException is thrown if one of the paths being
     * validated does not exist.
     */
    private void validatePathExists(String[] paths) throws FileNotFoundException {
        for (String path : paths) {
            validatePathExists(path);
        }
    }

    /**
     * Validates whether or not the path points at a file that exists; if the
     * path does not point to an existing file a FileNotFoundException is
     * thrown.
     *
     * @param path the paths to validate if they exists
     * @throws FileNotFoundException is thrown if the path being validated does
     * not exist.
     */
    private void validatePathExists(String path) throws FileNotFoundException {
        File f = new File(path);
        if (!f.exists()) {
            isValid = false;
            throw new FileNotFoundException("Invalid file argument: " + path);
        }
    }

    /**
     * Generates an Options collection that is used to parse the command line
     * and to display the help message.
     *
     * @return the command line options used for parsing the command line
     */
    @SuppressWarnings("static-access")
    private Options createCommandLineOptions() {
        Option help = new Option(ArgumentName.HELP_SHORT, ArgumentName.HELP, false,
                "print this message.");

        Option advancedHelp = new Option(ArgumentName.ADVANCED_HELP_SHORT, ArgumentName.ADVANCED_HELP, false,
                "shows additional help regarding properties file.");

        Option version = new Option(ArgumentName.VERSION_SHORT, ArgumentName.VERSION,
                false, "print the version information.");

        Option noupdate = new Option(ArgumentName.DISABLE_AUTO_UPDATE_SHORT, ArgumentName.DISABLE_AUTO_UPDATE,
                false, "disables the automatic updating of the CPE data.");

        Option appname = OptionBuilder.withArgName("name").hasArg().withLongOpt(ArgumentName.APPNAME)
                .withDescription("the name of the application being scanned.")
                .create(ArgumentName.APPNAME_SHORT);

        Option path = OptionBuilder.withArgName("path").hasArg().withLongOpt(ArgumentName.SCAN)
                .withDescription("the path to scan - this option can be specified multiple times.")
                .create(ArgumentName.SCAN_SHORT);

        Option props = OptionBuilder.withArgName("file").hasArg().withLongOpt(ArgumentName.PROP)
                .withDescription("a property file to load.")
                .create(ArgumentName.PROP_SHORT);

        Option out = OptionBuilder.withArgName("folder").hasArg().withLongOpt(ArgumentName.OUT)
                .withDescription("the folder to write reports to.")
                .create(ArgumentName.OUT_SHORT);

        Option outputformat = OptionBuilder.withArgName("format").hasArg().withLongOpt(ArgumentName.OUTPUT_FORMAT)
                .withDescription("the output format to write to.")
                .create(ArgumentName.OUTPUT_FORMAT_SHORT);

        //TODO add the ability to load a properties file to override the defaults...

        OptionGroup og = new OptionGroup();
        og.addOption(path);

        Options opts = new Options();
        opts.addOptionGroup(og);
        opts.addOption(out);
        opts.addOption(outputformat);
        opts.addOption(appname);
        opts.addOption(version);
        opts.addOption(help);
        opts.addOption(noupdate);
        opts.addOption(props);
        opts.addOption(advancedHelp);
        return opts;
    }

    /**
     * Determines if the 'version' command line argument was passed in.
     *
     * @return whether or not the 'version' command line argument was passed in
     */
    public boolean isGetVersion() {
        return (line != null) ? line.hasOption(ArgumentName.VERSION) : false;
    }

    /**
     * Determines if the 'help' command line argument was passed in.
     *
     * @return whether or not the 'help' command line argument was passed in
     */
    public boolean isGetHelp() {
        return (line != null) ? line.hasOption(ArgumentName.HELP) : false;
    }

    /**
     * Determines if the 'scan' command line argument was passed in.
     *
     * @return whether or not the 'scan' command line argument was passed in
     */
    public boolean isRunScan() {
        return (line != null) ? isValid && line.hasOption(ArgumentName.SCAN) : false;
    }

    /**
     * Displays the command line help message to the standard output.
     */
    public void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        String nl = System.getProperty("line.separator");
        String advancedHelp = null;
        if (line.hasOption(ArgumentName.ADVANCED_HELP)) {
            advancedHelp = nl + nl
                    + "Additionally, the following properties are supported and can be specified either"
                    + "using the -p <file> argument or by passing them in as system properties." + nl
                    + nl + " " + Settings.KEYS.PROXY_URL + "\t\t    the proxy URL to use when downloading resources."
                    + nl + " " + Settings.KEYS.PROXY_PORT + "\t\t    the proxy port to use when downloading resources."
                    + nl + " " + Settings.KEYS.CONNECTION_TIMEOUT + "\t    the connection timeout (in milliseconds) to use"
                    + nl + "\t\t\t    when downloading resources.";
        }

        formatter.printHelp(Settings.getString("application.name", "DependencyCheck"),
                nl + Settings.getString("application.name", "DependencyCheck")
                + " can be used to identify if there are any known CVE vulnerabilities in libraries utilized by an application. "
                + Settings.getString("application.name", "DependencyCheck")
                + " will automatically update required data from the Internet, such as the CVE and CPE data files from nvd.nist.gov." + nl + nl,
                options,
                "",
                true);
        if (advancedHelp != null) {
            System.out.println(advancedHelp);
        }
    }

    /**
     * Retrieves the file command line parameter(s) specified for the 'scan'
     * argument.
     *
     * @return the file paths specified on the command line for scan
     */
    public String[] getScanFiles() {
        return line.getOptionValues(ArgumentName.SCAN);

    }

    /**
     * returns the directory to write the reports to specified on the command
     * line.
     *
     * @return the path to the reports directory.
     */
    public String getReportDirectory() {
        return line.getOptionValue(ArgumentName.OUT);
    }

    /**
     * Returns the output format specified on the command line. Defaults to
     * HTML if no format was specified.
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
        return line.getOptionValue(ArgumentName.APPNAME);
    }

    /**
     * <p>Prints the manifest information to standard output:</p>
     * <ul><li>Implementation-Title: ${pom.name}</li>
     * <li>Implementation-Version: ${pom.version}</li></ul>
     */
    public void printVersionInfo() {
        String version = String.format("%s version %s",
                Settings.getString("application.name", "DependencyCheck"),
                Settings.getString("application.version", "Unknown"));
        System.out.println(version);
    }

    /**
     * Checks if the auto update feature has been disabled. If it has been
     * disabled via the command line this will return false.
     *
     * @return if auto-update is allowed.
     */
    public boolean isAutoUpdate() {
        return (line != null) ? !line.hasOption(ArgumentName.DISABLE_AUTO_UPDATE) : true;
    }

    /**
     * A collection of static final strings that represent the possible command
     * line arguments.
     */
    public static class ArgumentName {

        /**
         * The long CLI argument name specifing the directory/file to scan
         */
        public static final String SCAN = "scan";
        /**
         * The short CLI argument name specifing the directory/file to scan
         */
        public static final String SCAN_SHORT = "s";
        /**
         * The long CLI argument name specifing that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE = "noupdate";
        /**
         * The short CLI argument name specifing that the CPE/CVE/etc. data
         * should not be automatically updated.
         */
        public static final String DISABLE_AUTO_UPDATE_SHORT = "n";
        /**
         * The long CLI argument name specifing the directory to write the
         * reports to.
         */
        public static final String OUT = "out";
        /**
         * The short CLI argument name specifing the directory to write the
         * reports to.
         */
        public static final String OUT_SHORT = "o";
        /**
         * The long CLI argument name specifing the output format to write the
         * reports to.
         */
        public static final String OUTPUT_FORMAT = "format";
        /**
         * The short CLI argument name specifing the output format to write the
         * reports to.
         */
        public static final String OUTPUT_FORMAT_SHORT = "f";
        /**
         * The long CLI argument name specifing the name of the application to
         * be scanned.
         */
        public static final String APPNAME = "app";
        /**
         * The short CLI argument name specifing the name of the application to
         * be scanned.
         */
        public static final String APPNAME_SHORT = "a";
        /**
         * The long CLI argument name asking for help.
         */
        public static final String HELP = "help";
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
         * The CLI argument name asking for advanced help.
         */
        public static final String ADVANCED_HELP_SHORT = "ah";
        /**
         * The short CLI argument name asking for advanced help.
         */
        public static final String ADVANCED_HELP = "advancedhelp";
        /**
         * The short CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP_SHORT = "p";
        /**
         * The CLI argument name for setting the location of an additional
         * properties file.
         */
        public static final String PROP = "propertyfile";
    }
}
