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

public enum UrlHostHint implements EcosystemHint {

    // note: all must be lowercase
    /**
     * Ruby ecosystem.
     */
    RUBY("ruby-lang.org", Ecosystem.RUBY),
    /**
     * Python ecosystem.
     */
    PYTHON("python.org", Ecosystem.PYTHON),
    /**
     * PHP ecosystem.
     */
    DRUPAL("drupal.org", Ecosystem.PHP),
    /**
     * Node.js ecosystem.
     */
    NODEJS("nodejs.org", Ecosystem.NODEJS),
    /**
     * Node.js ecosystem.
     */
    NODE_SECURITY("nodesecurity.io", Ecosystem.NODEJS),
    /**
     * Rust ecosystem.
     */
    RUST("rustsec.org", Ecosystem.RUST);

    /**
     * The keyword to identify the ecosystem.
     */
    private final String keyword;

    /**
     * The ecosystem for the keyword.
     */
    private final String ecosystem;

    /**
     * Constructs a new URL Host Hint to map the keyword to the ecosystem.
     *
     * @param keyword the keyword
     * @param ecosystem the ecosystem
     */
    UrlHostHint(String keyword, String ecosystem) {
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
        return EcosystemHintNature.URL_HOST;
    }

    @Override
    public String getValue() {
        return getKeyword();
    }

}
