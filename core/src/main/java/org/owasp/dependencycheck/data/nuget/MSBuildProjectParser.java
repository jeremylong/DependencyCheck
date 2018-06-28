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
 * Copyright (c) 2018 Paul Irwin. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import java.io.InputStream;
import java.util.List;

/**
 * Interface defining methods for parsing a MSBuild project file.
 *
 * @author paulirwin
 *
 */
public interface MSBuildProjectParser {

    /**
     * Parse an input stream and returns a collection of
     * {@link NugetPackageReference} objects.
     *
     * @param stream the input stream to parse
     * @return a collection of discovered package references
     * @throws MSBuildProjectParseException when an exception occurs
     */
    List<NugetPackageReference> parse(InputStream stream) throws MSBuildProjectParseException;
}
