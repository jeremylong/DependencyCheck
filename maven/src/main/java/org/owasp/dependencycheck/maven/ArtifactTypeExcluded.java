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
 * Copyright (c) 2017 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.utils.Filter;

/**
 * {@link Filter} implementation to exclude artifacts whose type matches a
 * regular expression.
 *
 * @author ercpe
 */
public class ArtifactTypeExcluded extends Filter<String> {

    /**
     * The regular expression for the exclusion filter.
     */
    private final String regex;

    /**
     * Creates a new instance.
     *
     * @param excludeRegex The regular expression to match the artifacts type
     * against
     */
    public ArtifactTypeExcluded(final String excludeRegex) {
        this.regex = excludeRegex;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean passes(final String artifactType) {

        return StringUtils.isNotEmpty(regex) && StringUtils.isNotEmpty(artifactType) && artifactType.matches(regex);
    }
}
