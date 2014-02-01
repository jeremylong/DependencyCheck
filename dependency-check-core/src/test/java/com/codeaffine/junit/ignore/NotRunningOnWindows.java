/**
 * *****************************************************************************
 * Copyright (c) 2013 Rüdiger Herrmann All rights reserved. This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors: Rüdiger Herrmann - initial API and implementation
 * ****************************************************************************
 */
package com.codeaffine.junit.ignore;

/**
 * The following NotRunningOnWindows class was taken from blog by Rüdiger Herrmann titled <a
 * href="http://www.codeaffine.com/2013/11/18/a-junit-rule-to-conditionally-ignore-tests/">
 * A JUnit Rule to Conditionally Ignore Tests</a>.
 *
 * @author Rüdiger Herrmann <rherrmann@codeaffine.com>
 */
public class NotRunningOnWindows implements ConditionalIgnoreRule.IgnoreCondition {

    @Override
    public boolean isSatisfied() {
        return !System.getProperty("os.name").startsWith("Windows");
    }
}
