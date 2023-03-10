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
 * Copyright (c) 2023 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.util.Properties;
import org.apache.commons.text.StringSubstitutor;
import org.apache.commons.text.lookup.StringLookup;

/**
 *
 * @author Jeremy Long
 */
public final class InterpolationUtil {

    private InterpolationUtil() {
    }

    /**
     * <p>
     * A utility function that will interpolate strings based on values given in
     * the properties file. It will also interpolate the strings contained
     * within the properties file so that properties can reference other
     * properties.</p>
     * <p>
     * <b>Note:</b> if there is no property found the reference will be removed.
     * In other words, if the interpolated string will be replaced with an empty
     * string.
     * </p>
     * <p>
     * Example:</p>
     * <code>
     * Properties p = new Properties();
     * p.setProperty("key", "value");
     * String s = interpolateString("'${key}' and '${nothing}'", p);
     * System.out.println(s);
     * </code>
     * <p>
     * Will result in:</p>
     * <code>
     * 'value' and ''
     * </code>
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced
     * within the text.
     * @return the interpolated text.
     */
    public static String interpolate(String text, Properties properties) {
        return interpolate(text, properties, SyntaxStyle.DEFAULT);
    }

    /**
     * <p>
     * A utility function that will interpolate strings based on values given in
     * the properties file. It will also interpolate the strings contained
     * within the properties file so that properties can reference other
     * properties.</p>
     * <p>
     * <b>Note:</b> if there is no property found the reference will be removed.
     * In other words, if the interpolated string will be replaced with an empty
     * string.
     * </p>
     * <p>
     * Example:</p>
     * <code>
     * Properties p = new Properties();
     * p.setProperty("key", "value");
     * String s = interpolateString("'${key}' and '${nothing}'", p);
     * System.out.println(s);
     * </code>
     * <p>
     * Will result in:</p>
     * <code>
     * 'value' and ''
     * </code>
     *
     * @param text the string that contains references to properties.
     * @param properties a collection of properties that may be referenced
     * within the text.
     * @param style the syntax style for the interpolation (MSBuild; "$(var)",
     * Default "${var}")"
     * @return the interpolated text.
     */
    public static String interpolate(String text, Properties properties, SyntaxStyle style) {
        if (null == text || null == properties) {
            return text;
        }
        final StringSubstitutor substitutor;
        if (style == SyntaxStyle.MSBUILD) {
            substitutor = new StringSubstitutor(new PropertyLookup(properties), "$(", ")", '$');
        } else {
            substitutor = new StringSubstitutor(new PropertyLookup(properties));
        }
        return substitutor.replace(text);
    }

    /**
     * The syntax style for the interpolation.
     */
    public enum SyntaxStyle {
        /**
         * Default variable interpolation. Example: '${var}'
         */
        DEFAULT,
        /**
         * MS Build variable interpolation. Example: '$(var)'
         */
        MSBUILD
    }

    /**
     * Utility class that can provide values from a Properties object to a
     * StringSubstitutor.
     */
    private static class PropertyLookup implements StringLookup {

        /**
         * Reference to the properties to lookup.
         */
        private final Properties props;

        /**
         * Constructs a new property lookup.
         *
         * @param props the properties to wrap.
         */
        PropertyLookup(Properties props) {
            this.props = props;
        }

        /**
         * Looks up the given property.
         *
         * @param key the key to the property
         * @return the value of the property specified by the key
         */
        @Override
        public String lookup(String key) {
            return props.getProperty(key, "");
        }
    }
}
