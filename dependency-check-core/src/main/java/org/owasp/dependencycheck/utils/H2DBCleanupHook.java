/*
 * Copyright 2017 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.utils;

/**
 *
 * @author jeremy
 */
public class H2DBCleanupHook extends Thread {

    private final H2DBLock lock;

    public H2DBCleanupHook(H2DBLock lock) {
        this.lock = lock;
    }

    @Override
    public void run() {
        lock.release();
    }
}
