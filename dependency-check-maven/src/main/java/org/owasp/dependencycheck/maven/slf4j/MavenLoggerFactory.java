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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven.slf4j;

import org.apache.maven.plugin.logging.Log;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;

/**
 * Created on 6/14/15.
 *
 * @author colezlaw
 */
public class MavenLoggerFactory implements ILoggerFactory {

    /**
     * A reference to the Maven log adapter.
     */
    private final MavenLoggerAdapter mavenLoggerAdapter;

    /**
     * Constructs a new logger factory.
     *
     * @param log a reference to the Maven log
     */
    public MavenLoggerFactory(Log log) {
        super();
        this.mavenLoggerAdapter = new MavenLoggerAdapter(log);
    }

    /**
     * Returns the Maven Logger Adapter.
     *
     * @param name ignored in this implementation
     * @return the maven logger adapter
     */
    @Override
    public Logger getLogger(String name) {
        return mavenLoggerAdapter;
    }
}
