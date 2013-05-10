/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;

/**
 * This analyzer ensures that the Spring Framework Core CPE identifiers are only associated
 * with the "core" jar files. If there are other Spring JARs, such as spring-beans, and
 * spring-core is in the scanned dependencies then only the spring-core will have a reference
 * to the CPE values (if there are any for the version of spring being used).
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 * @deprecated This class has been deprecated as it has been replaced by the BundlingAnalyzer
 */
@Deprecated
public class SpringCleaningAnalyzer extends AbstractAnalyzer implements Analyzer {

    /**
     * The set of file extensions supported by this analyzer.
     */
    private static final Set<String> EXTENSIONS = newHashSet("jar");
    /**
     * The name of the analyzer.
     */
    private static final String ANALYZER_NAME = "Jar Analyzer";
    /**
     * The phase that this analyzer is intended to run in.
     */
    private static final AnalysisPhase ANALYSIS_PHASE = AnalysisPhase.POST_IDENTIFIER_ANALYSIS;

    /**
     * Returns a list of file EXTENSIONS supported by this analyzer.
     *
     * @return a list of file EXTENSIONS supported by this analyzer.
     */
    public Set<String> getSupportedExtensions() {
        return EXTENSIONS;
    }

    /**
     * Returns the name of the analyzer.
     *
     * @return the name of the analyzer.
     */
    public String getName() {
        return ANALYZER_NAME;
    }

    /**
     * Returns whether or not this analyzer can process the given extension.
     *
     * @param extension the file extension to test for support
     * @return whether or not the specified file extension is supported by this
     * analyzer.
     */
    public boolean supportsExtension(String extension) {
        return EXTENSIONS.contains(extension);
    }

    /**
     * Returns the phase that the analyzer is intended to run in.
     *
     * @return the phase that the analyzer is intended to run in.
     */
    public AnalysisPhase getAnalysisPhase() {
        return ANALYSIS_PHASE;
    }

    /**
     * a list of spring versions.
     */
    private List<Identifier> springVersions;

    /**
     * Determines if several "spring" libraries were scanned and trims the
     * cpe:/a:springsource:spring_framework:[version] from the none "core" framework
     * if the core framework was part of the scan.
     *
     * @param dependency the dependency to analyze.
     * @param engine the engine that is scanning the dependencies
     * @throws AnalysisException is thrown if there is an error reading the JAR
     * file.
     */
    public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
        collectSpringFrameworkIdentifiers(engine);

        final List<Identifier> identifiersToRemove = new ArrayList<Identifier>();
        for (Identifier identifier : dependency.getIdentifiers()) {
            if (springVersions.contains(identifier) && !isCoreFramework(dependency.getFileName())) {
                identifiersToRemove.add(identifier);
            }
        }

        for (Identifier i : identifiersToRemove) {
            dependency.getIdentifiers().remove(i);
        }
    }

    /**
     * Cycles through the dependencies and creates a collection of the spring identifiers.
     *
     * @param engine the core engine.
     */
    private void collectSpringFrameworkIdentifiers(Engine engine) {
        //check to see if any of the libs are the core framework
        if (springVersions == null) {
            springVersions = new ArrayList<Identifier>();
            for (Dependency d : engine.getDependencies()) {
                if (supportsExtension(d.getFileExtension())) {
                    for (Identifier i : d.getIdentifiers()) {
                        if (isSpringFrameworkCpe(i)) {
                            if (isCoreFramework(d.getFileName())) {
                                springVersions.add(i);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Attempts to determine if the identifier is for the spring framework.
     *
     * @param identifier an identifier
     * @return whether or not it is believed to be a spring identifier
     */
    private boolean isSpringFrameworkCpe(Identifier identifier) {
        return "cpe".equals(identifier.getType())
                && (identifier.getValue().startsWith("cpe:/a:springsource:spring_framework:")
                || identifier.getValue().startsWith("cpe:/a:vmware:springsource_spring_framework"));
    }

    /**
     * Attempts to determine if the file name passed in is for the core spring-framework.
     *
     * @param filename a file name
     * @return whether or not it is believed the file name is for the core spring framework
     */
    private boolean isCoreFramework(String filename) {
        return filename.toLowerCase().matches("^spring([ _-]?core)?[ _-]?\\d.*");
    }
}
