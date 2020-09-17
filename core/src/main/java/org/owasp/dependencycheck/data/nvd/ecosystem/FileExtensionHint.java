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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

public enum FileExtensionHint implements EcosystemHint {

    // note: all must be lowercase
    /**
     * PHP file extension hint.
     */
    PHP(".php", Ecosystem.PHP),
    /**
     * Perl file extension hint.
     */
    PERL_PM(".pm", Ecosystem.PERL),
    /**
     * Perl file extension hint.
     */
    PERL_PL(".pl", Ecosystem.PERL),
    /**
     * Java file extension hint.
     */
    JAR_JAVA(".java", Ecosystem.JAVA),
    /**
     * Perl file extension hint.
     */
    JAR_JSP(".jsp", Ecosystem.JAVA),
    /**
     * Ruby file extension hint.
     */
    RUBY(".rb", Ecosystem.RUBY),
    /**
     * Python file extension hint.
     */
    PYTON(".py", Ecosystem.PYTHON),
    /**
     * C++ file extension hint.
     */
    CMAKE_CPP(".cpp", Ecosystem.NATIVE),
    /**
     * C file extension hint.
     */
    CMAKE_C(".c", Ecosystem.NATIVE),
    /**
     * C file extension hint.
     */
    CMAKE_H(".h", Ecosystem.NATIVE);

    /**
     * The file extension for the ecosystem.
     */
    private final String extension;
    /**
     * The ecosystem for the given file extension.
     */
    private final String ecosystem;

    /**
     * Constructs a new hint for the given file extension and ecosystem.
     *
     * @param extension the file extension to identify the given ecosystem
     * @param ecosystem the ecosystem for the given file extension
     */
    FileExtensionHint(String extension, String ecosystem) {
        this.extension = extension;
        this.ecosystem = ecosystem;
    }

    @Override
    public String getEcosystem() {
        return ecosystem;
    }

    public String getExtension() {
        return extension;
    }

    @Override
    public EcosystemHintNature getNature() {
        return EcosystemHintNature.FILE_EXTENSION;
    }

    @Override
    public String getValue() {
        return getExtension();
    }
}
