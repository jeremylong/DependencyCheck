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

public enum DescriptionKeywordHint implements EcosystemHint {

    // note: all must be lowercase
    NPM("npm", Ecosystem.NODEJS),
    NODEJS("node.js", Ecosystem.NODEJS),
    GRAILS("grails", Ecosystem.JAVA),
    RUBY_GEM("ruby gem", Ecosystem.RUBY),
    DJANGO("django", Ecosystem.PYTHON),
    BUFFER_OVERFLOW("buffer overflow", Ecosystem.CMAKE),
    BUFFER_OVERFLOWS("buffer overflows", Ecosystem.CMAKE),
    WORDPRESS("wordpress", Ecosystem.PHP),
    DRUPAL("drupal", Ecosystem.PHP),
    JOOMLA("joomla", Ecosystem.PHP),
    JOOMLA_EXCLAMATION_MARK("joomla!", Ecosystem.PHP),
    MOODLE("moodle", Ecosystem.PHP),
    TYPO3("typo3", Ecosystem.PHP),
    JAVA_SE("java se", Ecosystem.JAVA);

    private final String keyword;

    private final String ecosystem;

    private DescriptionKeywordHint(String keyword, String ecosystem) {
        this.keyword = keyword;
        this.ecosystem = ecosystem;
    }

    @Override
    public String getEcosystem() {
        return ecosystem;
    }

    public String getKeyword() {
        return keyword;
    }

    @Override
    public EcosystemHintNature getNature() {
        return EcosystemHintNature.KEYWORD;
    }

    @Override
    public String getValue() {
        return getKeyword();
    }

}
