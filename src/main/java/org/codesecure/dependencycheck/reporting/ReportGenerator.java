package org.codesecure.dependencycheck.reporting;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.context.Context;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader;
import org.apache.velocity.tools.ToolManager;
import org.apache.velocity.tools.config.EasyFactoryConfiguration;
import org.codesecure.dependencycheck.dependency.Dependency;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class ReportGenerator {

    /**
     * Generates the Dependency Reports for the identified dependencies.
     *
     * @param outputDir the path where the reports should be written.
     * @param applicationName the name of the application that was scanned.
     * @param dependencies a list of dependencies to include in the report.
     * @throws IOException is thrown when the template file does not exist.
     * @throws Exception is thrown if there is an error writting out the reports.
     */
    public void generateReports(String outputDir, String applicationName, List<Dependency> dependencies) throws IOException, Exception {

        Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("dependencies", dependencies);
        properties.put("applicationName", applicationName);

        String reportName = applicationName.replaceAll("[^a-zA-Z0-9-_ \\.]+", "");
        String filename = outputDir + File.separatorChar + reportName;
        generateReport("HtmlReport", filename + ".html", properties);
        //generateReport("XmlReport",filename + ".xml",properties);

    }

    /**
     * much of this code is from http://stackoverflow.com/questions/2931516/loading-velocity-template-inside-a-jar-file
     * @param templateName the name of the template to load.
     * @param outFileName The filename and path to write the report to.
     * @param properties a map of properties to load into the velocity context.
     * @throws IOException is thrown when the template file does not exist.
     * @throws Exception is thrown when an exception occurs.
     */
    protected void generateReport(String templateName, String outFileName,
            Map<String, Object> properties) throws IOException, Exception {

        VelocityEngine ve = new VelocityEngine();
        ve.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        ve.setProperty("classpath.resource.loader.class", ClasspathResourceLoader.class.getName());

        ToolManager manager = new ToolManager();
        Context context = manager.createContext();
        EasyFactoryConfiguration config = new EasyFactoryConfiguration();
        config.addDefaultTools();
        config.toolbox("application").tool("esc", "org.apache.velocity.tools.generic.EscapeTool").tool("org.apache.velocity.tools.generic.DateTool");

        manager.configure(config);

        ve.init();

        final String templatePath = "templates/" + templateName + ".vsl";
        InputStream input = this.getClass().getClassLoader().getResourceAsStream(templatePath);
        if (input == null) {
            throw new IOException("Template file doesn't exist");
        }

        InputStreamReader reader = new InputStreamReader(input);
        BufferedWriter writer = null;

        //VelocityContext context = new VelocityContext();

        //load the data into the context
        if (properties != null) {
            for (Map.Entry<String, Object> property : properties.entrySet()) {
                context.put(property.getKey(), property.getValue());
            }
        }

        try {
            writer = new BufferedWriter(new FileWriter(new File(outFileName)));

            if (!ve.evaluate(context, writer, templatePath, reader)) {
                throw new Exception("Failed to convert the template into html.");
            }
            writer.flush();
        } finally {
            try {
                writer.close();
            } catch (Exception ex) {
                Logger.getLogger(ReportGenerator.class.getName()).log(Level.FINEST, null, ex);
            }
            try {
                reader.close();
            } catch (Exception ex) {
                Logger.getLogger(ReportGenerator.class.getName()).log(Level.FINEST, null, ex);
            }
        }
    }
}
