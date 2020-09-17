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

import org.owasp.dependencycheck.utils.Settings;

/**
 * Collection of the standard ecosystems for dependency-check.
 *
 * @author Jeremy Long
 */
public final class Ecosystem {

    /**
     * The Ruby ecosystem.
     */
    public static final String RUBY = "ruby";
    /**
     * The dotnet ecosystem.
     */
    public static final String DOTNET = "dotnet";
    /**
     * The iOS ecosystem.
     */
    public static final String IOS = "ios";
    /**
     * The PHP ecosystem.
     */
    public static final String PHP = "php";
    /**
     * The Golang ecosystem.
     */
    public static final String GOLANG = "golang";
    /**
     * The Java ecosystem.
     */
    public static final String JAVA = "java";
    /**
     * The native ecosystem.
     */
    public static final String NATIVE = "native";
    /**
     * The Python ecosystem.
     */
    public static final String PYTHON = "python";
    /**
     * The JavaScript ecosystem.
     */
    public static final String JAVASCRIPT = "js";
    /**
     * The Node.JS ecosystem.
     */
    public static final String NODEJS = "nodejs";
    /**
     * The rust ecosystem.
     */
    public static final String RUST = "rust";
    /**
     * The rust ecosystem.
     */
    public static final String COLDFUSION = "coldfusion";
    /**
     * The Perl ecosystem.
     */
    public static final String PERL = "perl";
    /**
     * The Elixir ecosystem.
     */
    public static final String ELIXIR = "exlixir";

    /**
     * A reference to the ODC settings.
     */
    private final Settings settings;
    /**
     * The lucene default query size.
     */
    private final int defaultQuerySize;

    /**
     * Instantiates the ecosystem utility class.
     *
     * @param settings the ODC configuration
     */
    public Ecosystem(Settings settings) {
        this.settings = settings;
        this.defaultQuerySize = settings.getInt(Settings.KEYS.MAX_QUERY_SIZE_DEFAULT, 100);
    }

    /**
     * Returns the max query result size for the Lucene search for each
     * ecosystem.
     *
     * @param ecosystem the ecosystem
     * @return the max query result size
     */
    public int getLuceneMaxQueryLimitFor(String ecosystem) {
        return settings.getInt(Settings.KEYS.MAX_QUERY_SIZE_PREFIX + ecosystem, defaultQuerySize);
    }
}
