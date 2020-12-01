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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.processing;

import java.io.InputStream;
import org.owasp.dependencycheck.utils.processing.Processor;
import org.owasp.dependencycheck.xml.assembly.AssemblyData;
import org.owasp.dependencycheck.xml.assembly.GrokParseException;
import org.owasp.dependencycheck.xml.assembly.GrokParser;

/**
 * Processor for the output of GrokAssembly.exe.
 *
 * @author Jeremy Long
 */
public class GrokAssemblyProcessor extends Processor<InputStream> {

    /**
     * Temporary storage for an exception if it occurs during the processing.
     */
    private GrokParseException exception;
    /**
     * The assembly data retrieved from grok assembly.
     */
    private AssemblyData assemblyData;

    /**
     * Returns the assembly data.
     *
     * @return the assembly data
     */
    public AssemblyData getAssemblyData() {
        return assemblyData;
    }

    @Override
    public void run() {
        final GrokParser grok = new GrokParser();
        try {
            assemblyData = grok.parse(getInput());
        } catch (GrokParseException ex) {
            exception = ex;
        }
    }

    /**
     * Throws any exceptions that occurred during processing.
     *
     * @throws GrokParseException thrown if there is an error parsing the output
     * of GrokAssembly
     */
    @Override
    public void close() throws GrokParseException {
        if (exception != null) {
            throw exception;
        }
    }
}
