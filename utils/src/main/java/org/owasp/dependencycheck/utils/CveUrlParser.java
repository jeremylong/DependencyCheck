/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2021 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

/**
 * Interface providing a parser for an NVD CVE URL.
 *
 * The goal of this parser is to provide methods to manipulate these URLs.
 *
 * @author nhumblot
 *
 */
public interface CveUrlParser {

    /**
     * Create a new instance of the CveUrlParser.
     *
     * @param settings the configured settings
     * @return the new instance
     */
    static CveUrlParser newInstance(Settings settings) {
        return new DefaultCveUrlModifiedParser(settings);
    }

    /**
     * Gets the default CVE Modified URL.
     *
     * @param baseUrl the base CVE URL
     * @return the default CVE Modified URL
     */
    String getDefaultCveUrlModified(String baseUrl);

}
