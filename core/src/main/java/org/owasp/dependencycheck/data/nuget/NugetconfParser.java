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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nuget;

import java.io.InputStream;
import java.util.List;

/**
 * Interface defining methods for parsing a packages.config file.
 *
 * @author doshyt
 *
 */
public interface NugetconfParser {

    /**
     * Parse an input stream and return the resulting {@link NugetPackage}.
     *
     * @param stream the input stream to parse
     * @return the populated bean
     * @throws NugetconfParseException when an exception occurs
     */
    List<NugetPackageReference> parse(InputStream stream) throws NugetconfParseException;
}
