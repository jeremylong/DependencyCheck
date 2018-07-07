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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.io.File;
import java.io.IOException;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.io.FileUtils;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jeremy
 */
@ThreadSafe
public final class PomUtils {

    /**
     * empty private constructor for utility class.
     */
    private PomUtils() {
    }
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PomUtils.class);

    /**
     * Reads in the specified POM and converts it to a Model.
     *
     * @param file the pom.xml file
     * @return returns an object representation of the POM
     * @throws AnalysisException is thrown if there is an exception extracting
     * or parsing the POM {@link Model} object
     */
    public static Model readPom(File file) throws AnalysisException {
        //noinspection CaughtExceptionImmediatelyRethrown
        try {
            final PomParser parser = new PomParser();
            final Model model = parser.parse(file);
            if (model == null) {
                throw new AnalysisException(String.format("Unable to parse pom '%s'", file.getPath()));
            }
            return model;
        } catch (AnalysisException ex) {
            throw ex;
        } catch (PomParseException ex) {
            LOGGER.warn("Unable to parse pom '{}'", file.getPath());
            //todo remove test code for intermittent error.
            try {
                final File target = new File("~/Projects/DependencyCheck/core/target/");
                if (target.isDirectory()) {
                    FileUtils.copyFile(file, target);
                    LOGGER.info("Unparsable pom was copied to {}", target.toString());
                }
            } catch (IOException ex1) {
                throw new RuntimeException(ex1);
            }
            LOGGER.debug("", ex);
            throw new AnalysisException(ex);
        } catch (Throwable ex) {
            LOGGER.warn("Unexpected error during parsing of the pom '{}'", file.getPath());
            LOGGER.debug("", ex);
            throw new AnalysisException(ex);
        }
    }

    /**
     * Retrieves the specified POM from a jar file and converts it to a Model.
     *
     * @param path the path to the pom.xml file within the jar file
     * @param jar the jar file to extract the pom from
     * @return returns an object representation of the POM
     * @throws AnalysisException is thrown if there is an exception extracting
     * or parsing the POM {@link Model} object
     */
    public static Model readPom(String path, JarFile jar) throws AnalysisException {
        final ZipEntry entry = jar.getEntry(path);
        Model model = null;
        if (entry != null) { //should never be null
            //noinspection CaughtExceptionImmediatelyRethrown
            try {
                final PomParser parser = new PomParser();
                model = parser.parse(jar.getInputStream(entry));
                if (model == null) {
                    throw new AnalysisException(String.format("Unable to parse pom '%s/%s'", jar.getName(), path));
                }
            } catch (AnalysisException ex) {
                throw ex;
            } catch (SecurityException ex) {
                LOGGER.warn("Unable to parse pom '{}' in jar '{}'; invalid signature", path, jar.getName());
                LOGGER.debug("", ex);
                throw new AnalysisException(ex);
            } catch (IOException ex) {
                LOGGER.warn("Unable to parse pom '{}' in jar '{}' (IO Exception)", path, jar.getName());
                LOGGER.debug("", ex);
                throw new AnalysisException(ex);
            } catch (Throwable ex) {
                LOGGER.warn("Unexpected error during parsing of the pom '{}' in jar '{}'", path, jar.getName());
                LOGGER.debug("", ex);
                throw new AnalysisException(ex);
            }
        }
        return model;
    }

    /**
     * Reads in the pom file and adds elements as evidence to the given
     * dependency.
     *
     * @param dependency the dependency being analyzed
     * @param pomFile the pom file to read
     * @throws AnalysisException is thrown if there is an exception parsing the
     * pom
     */
    public static void analyzePOM(Dependency dependency, File pomFile) throws AnalysisException {
        final Model pom = PomUtils.readPom(pomFile);
        JarAnalyzer.setPomEvidence(dependency, pom, null);
    }
}
