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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.taskdefs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.impl.StaticLoggerBinder;

/**
 * An Ant task definition to execute dependency-check during an Ant build.
 *
 * @author Jeremy Long
 */
public class Purge extends Task {

    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "task.properties";

    /**
     * Construct a new DependencyCheckTask.
     */
    public Purge() {
        super();
        // Call this before Dependency Check Core starts logging anything - this way, all SLF4J messages from
        // core end up coming through this tasks logger
        StaticLoggerBinder.getSingleton().setTask(this);
    }

    /**
     * The location of the data directory that contains
     */
    private String dataDirectory = null;

    /**
     * Get the value of dataDirectory.
     *
     * @return the value of dataDirectory
     */
    public String getDataDirectory() {
        return dataDirectory;
    }

    /**
     * Set the value of dataDirectory.
     *
     * @param dataDirectory new value of dataDirectory
     */
    public void setDataDirectory(String dataDirectory) {
        this.dataDirectory = dataDirectory;
    }

    @Override
    public void execute() throws BuildException {
        populateSettings();
        File db;
        try {
            db = new File(Settings.getDataDirectory(), "dc.h2.db");
            if (db.exists()) {
                if (db.delete()) {
                    log("Database file purged; local copy of the NVD has been removed", Project.MSG_INFO);
                } else {
                    log(String.format("Unable to delete '%s'; please delete the file manually", db.getAbsolutePath()), Project.MSG_ERR);
                }
            } else {
                log(String.format("Unable to purge database; the database file does not exists: %s", db.getAbsolutePath()), Project.MSG_ERR);
            }
        } catch (IOException ex) {
            log("Unable to delete the database", Project.MSG_ERR);
        } finally {
            Settings.cleanup(true);
        }
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings. Additionally, this sets the system properties
     * required to change the proxy server, port, and connection timeout.
     */
    protected void populateSettings() {
        Settings.initialize();
        InputStream taskProperties = null;
        try {
            taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            Settings.mergeProperties(taskProperties);
        } catch (IOException ex) {
            log("Unable to load the dependency-check ant task.properties file.", ex, Project.MSG_WARN);
        } finally {
            if (taskProperties != null) {
                try {
                    taskProperties.close();
                } catch (IOException ex) {
                    log("", ex, Project.MSG_DEBUG);
                }
            }
        }
        if (dataDirectory != null) {
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else {
            final File jarPath = new File(Purge.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            final File base = jarPath.getParentFile();
            final String sub = Settings.getString(Settings.KEYS.DATA_DIRECTORY);
            final File dataDir = new File(base, sub);
            Settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        }
    }
}
