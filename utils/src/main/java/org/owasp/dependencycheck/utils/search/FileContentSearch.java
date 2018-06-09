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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils.search;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * Utility for searching files.
 *
 * @author Jeremy Long
 */
public final class FileContentSearch {

    /**
     * Private constructor for a utility class.
     */
    private FileContentSearch() {
        //empty constructor for utility class.
    }

    public static boolean contains(File file, String pattern) throws IOException {
        try (Scanner fileScanner = new Scanner(file)) {
            final Pattern regex = Pattern.compile(pattern);
            if (fileScanner.findWithinHorizon(regex, 0) != null) {
                return true;
            }
        }
        return false;
    }

    public static boolean contains(File file, List<String> patterns) throws IOException {
        List<Pattern> regexes = new ArrayList<>();
        for (String pattern : patterns) {
            regexes.add(Pattern.compile(pattern));
        }
        try (Scanner fileScanner = new Scanner(file)) {
            for (Pattern regex : regexes) {
                if (fileScanner.findWithinHorizon(regex, 0) != null) {
                    return true;
                }
            }
        }
        return false;
    }
}
