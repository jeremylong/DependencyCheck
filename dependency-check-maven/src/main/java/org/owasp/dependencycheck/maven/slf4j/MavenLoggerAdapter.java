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
import org.slf4j.helpers.MarkerIgnoringBase;
import org.slf4j.helpers.MessageFormatter;

/**
 * Created on 6/14/15.
 *
 * @author colezlaw
 */
public class MavenLoggerAdapter extends MarkerIgnoringBase {

    /**
     * A reference to the Maven log.
     */
    private final Log log;

    /**
     * Creates a new Maven Logger Adapter.
     *
     * @param log the Maven log
     */
    public MavenLoggerAdapter(Log log) {
        super();
        this.log = log;
    }

    /**
     * Returns true if trace is enabled.
     *
     * @return whether or not trace is enabled
     */
    @Override
    public boolean isTraceEnabled() {
        if (log != null) {
            return log.isDebugEnabled();
        }
        return true;
    }

    @Override
    public void trace(String msg) {
        if (log != null) {
            log.debug(msg);
        } else {
            System.out.println(msg);
        }
    }

    @Override
    public void trace(String format, Object arg) {
        final String message = MessageFormatter.format(format, arg).getMessage();
        if (log != null) {
            log.debug(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void trace(String format, Object arg1, Object arg2) {
        final String message = MessageFormatter.format(format, arg1, arg2).getMessage();
        if (log != null) {
            log.debug(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void trace(String format, Object... arguments) {
        final String message = MessageFormatter.format(format, arguments).getMessage();
        if (log != null) {
            log.debug(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void trace(String msg, Throwable t) {
        if (log != null) {
            log.debug(msg, t);
        } else {
            System.out.println(msg);
            t.printStackTrace();
        }
    }

    @Override
    public boolean isDebugEnabled() {
        if (log != null) {
            return log.isDebugEnabled();
        }
        return true;
    }

    @Override
    public void debug(String msg) {
        if (log != null) {
            log.debug(msg);
        } else {
            System.out.println(msg);
        }
    }

    @Override
    public void debug(String format, Object arg) {
        final String message = MessageFormatter.format(format, arg).getMessage();
        if (log != null) {
            log.debug(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void debug(String format, Object arg1, Object arg2) {
        final String message = MessageFormatter.format(format, arg1, arg2).getMessage();
        if (log != null) {
            log.debug(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void debug(String format, Object... arguments) {
        final String message = MessageFormatter.format(format, arguments).getMessage();
        if (log != null) {
            log.debug(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void debug(String msg, Throwable t) {
        if (log != null) {
            log.debug(msg, t);
        } else {
            System.out.println(msg);
            t.printStackTrace();
        }
    }

    @Override
    public boolean isInfoEnabled() {
        if (log != null) {
            return log.isInfoEnabled();
        }
        return true;
    }

    @Override
    public void info(String msg) {
        if (log != null) {
            log.info(msg);
        } else {
            System.out.println(msg);
        }
    }

    @Override
    public void info(String format, Object arg) {
        final String message = MessageFormatter.format(format, arg).getMessage();
        if (log != null) {
            log.info(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void info(String format, Object arg1, Object arg2) {
        final String message = MessageFormatter.format(format, arg1, arg2).getMessage();
        if (log != null) {
            log.info(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void info(String format, Object... arguments) {
        final String message = MessageFormatter.format(format, arguments).getMessage();
        if (log != null) {
            log.info(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void info(String msg, Throwable t) {
        if (log != null) {
            log.info(msg, t);
        } else {
            System.out.println(msg);
            t.printStackTrace();
        }
    }

    @Override
    public boolean isWarnEnabled() {
        if (log != null) {
            return log.isWarnEnabled();
        }
        return true;
    }

    @Override
    public void warn(String msg) {
        if (log != null) {
            log.warn(msg);
        } else {
            System.out.println(msg);
        }
    }

    @Override
    public void warn(String format, Object arg) {
        final String message = MessageFormatter.format(format, arg).getMessage();
        if (log != null) {
            log.warn(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void warn(String format, Object arg1, Object arg2) {
        final String message = MessageFormatter.format(format, arg1, arg2).getMessage();
        if (log != null) {
            log.warn(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void warn(String format, Object... arguments) {
        final String message = MessageFormatter.format(format, arguments).getMessage();
        if (log != null) {
            log.warn(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void warn(String msg, Throwable t) {
        if (log != null) {
            log.warn(msg, t);
        } else {
            System.out.println(msg);
            t.printStackTrace();
        }
    }

    @Override
    public boolean isErrorEnabled() {
        if (log != null) {
            return log.isErrorEnabled();
        }
        return true;
    }

    @Override
    public void error(String msg) {
        if (log != null) {
            log.error(msg);
        } else {
            System.out.println(msg);
        }
    }

    @Override
    public void error(String format, Object arg) {
        final String message = MessageFormatter.format(format, arg).getMessage();
        if (log != null) {
            log.error(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void error(String format, Object arg1, Object arg2) {
        final String message = MessageFormatter.format(format, arg1, arg2).getMessage();
        if (log != null) {
            log.error(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void error(String format, Object... arguments) {
        final String message = MessageFormatter.format(format, arguments).getMessage();
        if (log != null) {
            log.error(message);
        } else {
            System.out.println(message);
        }
    }

    @Override
    public void error(String msg, Throwable t) {
        if (log != null) {
            log.error(msg, t);
        } else {
            System.out.println(msg);
            t.printStackTrace();
        }
    }
}
