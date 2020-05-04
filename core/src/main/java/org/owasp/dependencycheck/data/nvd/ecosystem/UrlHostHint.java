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
    RUBY("ruby-lang.org", Ecosystem.RUBY),
    PYTHON("python.org", Ecosystem.PYTHON),
    DRUPAL("drupal.org", Ecosystem.PHP),
    NODEJS("nodejs.org", Ecosystem.NODEJS),
    NODE_SECURITY("nodesecurity.io", Ecosystem.NODEJS),
    RUST("rustsec.org", Ecosystem.RUST);

    private final String keyword;

    private final String ecosystem;

    private UrlHostHint(String keyword, String ecosystem) {
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
