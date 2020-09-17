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

/**
 * Enumeration used for mapping CVEs to their ecosystems based on the
 * description.
 *
 * @author skjolber
 */
public enum DescriptionKeywordHint implements EcosystemHint {

    // note: all must be lowercase
    /**
     * The NPM Ecosystem (node.js).
     */
    NPM("npm", Ecosystem.NODEJS),
    /**
     * The node.js ecosystem.
     */
    NODEJS("node.js", Ecosystem.NODEJS),
    /**
     * The grails ecosystem (java).
     */
    GRAILS("grails", Ecosystem.JAVA),
    /**
     * The ruby ecosystem.
     */
    RUBY_GEM("ruby gem", Ecosystem.RUBY),
    /**
     * The django ecosystem.
     */
    DJANGO("django", Ecosystem.PYTHON),
    /**
     * Description text to identify native ecosystems.
     */
    BUFFER_OVERFLOW("buffer overflow", Ecosystem.NATIVE),
    /**
     * Description text to identify native ecosystems.
     */
    BUFFER_OVERFLOWS("buffer overflows", Ecosystem.NATIVE),
    /**
     * The word press ecosystem (PHP).
     */
    WORDPRESS("wordpress", Ecosystem.PHP),
    /**
     * The drupal ecosystem (PHP).
     */
    DRUPAL("drupal", Ecosystem.PHP),
    /**
     * The joomla ecosystem (PHP).
     */
    JOOMLA("joomla", Ecosystem.PHP),
    /**
     * The joomla ecosystem (PHP).
     */
    JOOMLA_EXCLAMATION_MARK("joomla!", Ecosystem.PHP),
    /**
     * The moodle ecosystem (PHP).
     */
    MOODLE("moodle", Ecosystem.PHP),
    /**
     * The typo3 ecosystem (PHP).
     */
    TYPO3("typo3", Ecosystem.PHP),
    /**
     * The Java ecosystem (Java).
     */
    JAVA_SE("java se", Ecosystem.JAVA),
    /**
     * The Java ecosystem (Java).
     */
    JAVA_EE("java ee", Ecosystem.JAVA);

    /**
     * The keyword for the description identification.
     */
    private final String keyword;
    /**
     * The ecosystem identified by the keyword.
     */
    private final String ecosystem;

    /**
     * Constructs a new keyword hint.
     *
     * @param keyword the keyword contained in CVE descriptions
     * @param ecosystem the ecosystem identified by the keyword
     */
    DescriptionKeywordHint(String keyword, String ecosystem) {
        this.keyword = keyword;
        this.ecosystem = ecosystem;
    }

    /**
     * Returns the ecosystem.
     *
     * @return the ecosystem
     */
    @Override
    public String getEcosystem() {
        return ecosystem;
    }

    /**
     * Returns the keyword.
     *
     * @return the keyword
     */
    public String getKeyword() {
        return keyword;
    }

    /**
     * Returns the nature.
     *
     * @return the nature
     */
    @Override
    public EcosystemHintNature getNature() {
        return EcosystemHintNature.KEYWORD;
    }

    /**
     * Returns the keyword.
     *
     * @return the keyword
     */
    @Override
    public String getValue() {
        return getKeyword();
    }

}
