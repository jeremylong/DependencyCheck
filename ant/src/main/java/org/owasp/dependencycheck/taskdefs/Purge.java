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
     * The configured settings.
     */
    private Settings settings;

    /**
     * The location of the data directory that contains
     */
    private String dataDirectory = null;
    /**
     * Indicates if dependency-check should fail the build if an exception
     * occurs.
     */
    private boolean failOnError = true;

    /**
     * Construct a new DependencyCheckTask.
     */
    public Purge() {
        super();

        // Call this before Dependency Check Core starts logging anything - this way, all SLF4J messages from
        // core end up coming through this tasks logger
        StaticLoggerBinder.getSingleton().setTask(this);
    }

    public Settings getSettings() {
        return settings;
    }

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

    /**
     * Get the value of failOnError.
     *
     * @return the value of failOnError
     */
    public boolean isFailOnError() {
        return failOnError;
    }

    /**
     * Set the value of failOnError.
     *
     * @param failOnError new value of failOnError
     */
    public void setFailOnError(boolean failOnError) {
        this.failOnError = failOnError;
    }

    /**
     * Executes the dependency-check purge to delete the existing local copy of
     * the NVD CVE data.
     *
     * @throws BuildException thrown if there is a problem deleting the file(s)
     */
    @Override
    public void execute() throws BuildException {
        populateSettings();
        final File db;
        try {
            db = new File(getSettings().getDataDirectory(), getSettings().getString(Settings.KEYS.DB_FILE_NAME, "dc.mv.db"));
            if (db.exists()) {
                if (db.delete()) {
                    log("Database file purged; local copy of the NVD has been removed", Project.MSG_INFO);
                } else {
                    final String msg = String.format("Unable to delete '%s'; please delete the file manually", db.getAbsolutePath());
                    if (this.failOnError) {
                        throw new BuildException(msg);
                    }
                    log(msg, Project.MSG_ERR);
                }
            } else {
                final String msg = String.format("Unable to purge database; the database file does not exist: %s", db.getAbsolutePath());
                if (this.failOnError) {
                    throw new BuildException(msg);
                }
                log(msg, Project.MSG_ERR);
            }
        } catch (IOException ex) {
            final String msg = "Unable to delete the database";
            if (this.failOnError) {
                throw new BuildException(msg);
            }
            log(msg, Project.MSG_ERR);
        } finally {
            settings.cleanup(true);
        }
    }

    /**
     * Takes the properties supplied and updates the dependency-check settings.
     * Additionally, this sets the system properties required to change the
     * proxy server, port, and connection timeout.
     *
     * @throws BuildException thrown if the properties file cannot be read.
     */
    protected void populateSettings() throws BuildException {
        settings = new Settings();
        try (InputStream taskProperties = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            settings.mergeProperties(taskProperties);
        } catch (IOException ex) {
            final String msg = "Unable to load the dependency-check ant task.properties file.";
            if (this.failOnError) {
                throw new BuildException(msg, ex);
            }
            log(msg, ex, Project.MSG_WARN);
        }
        if (dataDirectory != null) {
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDirectory);
        } else {
            final File jarPath = new File(Purge.class.getProtectionDomain().getCodeSource().getLocation().getPath());
            final File base = jarPath.getParentFile();
            final String sub = settings.getString(Settings.KEYS.DATA_DIRECTORY);
            final File dataDir = new File(base, sub);
            settings.setString(Settings.KEYS.DATA_DIRECTORY, dataDir.getAbsolutePath());
        }
    }
}
