# configure.ac - configuration for "readable" project.
# For more information on the project, see: http://readable.sourceforge.net.
# For autotools info, see: http://www.dwheeler.com/autotools

# Copyright (C) 2007-2013 by David A. Wheeler and Alan Manuel K. Gloria.
#
# This software is released as open source software under the "MIT" license:
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.


# This "configure" script tries to "automagically" configure the software
# for the user's system.
# In general we will try to generate a "configure" that will
# "work with what we have" but warn if major components aren't available.
# We'll check for file existence for convenience (most users will configure
# for their OWN system).  We'll also provide override mechanisms to skip that,
# to support generation for other systems (cross-"compiling").


# Version numbers generally follow the Semantic Versioning convention
# (MAJOR.MINOR.PATCH) as documented here: http://semver.org/
# Pre-release values DO NOT INCLUDE a hyphen,
# because hyphens are specifically forbidden by RPM-based tools
# (used by Red Hat Enterprise Linux, Fedora, CentOS, SuSE, etc.).

# Initialize, but use more options.  Note parameter brackets and whitespace.
# TO CHANGE THE VERSION NUMBER: Edit readable-simple.spec, readable.spec,
# readable.asd, possibly ChangeLog, and the line below:
AC_INIT([readable], [1.0.7], [dwheeler@dwheeler.com],
        [readable], [http://readable.sourceforge.net/])
AC_COPYRIGHT(
[[Copyright (C) 2007-2014 by David A. Wheeler and Alan Manuel K. Gloria.
This software is Free/libre/open source software and is
released under the "MIT" license.]])

# Force autoconf to be more recent.
AC_PREREQ([2.63])
# Safety check - list a source file that wouldn't be in other projects:
AC_CONFIG_SRCDIR([src/kernel.scm])
# Put autotools auxiliary files in a subdir, so they don't clutter top dir:
AC_CONFIG_AUX_DIR([build-aux])

# Enable "automake" to simplify creating makefiles:
AM_INIT_AUTOMAKE([1.11 -Wall -Werror])
AC_CONFIG_FILES([Makefile])

# Supporting shell functions
is_empty () {
  test "x$1" = "x"
}

is_enabled () { # Return TRUE if $1 has non-no value; empty considered enabled
  test "x$1" != "xno"
}

is_permitted () { # Return TRUE if $1 has non-no value; empty = permitted
  test "x$1" != "xno"
}

is_no_or_empty () {
  if "x$1" = "xno" ; then
    true
  elif test "x$1" = "x" ; then
    true
  else
    false
  fi
}

# Report if given a "useful" value (something other than yes, no, or empty)
is_useful () {
  if test "x$1" = "xyes" ; then
    false
  elif test "x$1" = "xno" ; then
    false
  elif test "x$1" = "x" ; then
    false
  else
    true
  fi
}

# We generate HTML files from markdown files. By default we do this
# using the markdown2.py file (MIT license), copied from:
#   https://raw.github.com/trentm/python-markdown2/master/lib/markdown2.py
# We have our own copy in our directory so we can be certain to have one.
# Users can use MARKDOWN=... or --markdown=... to use their own.
default_markdown_command='python "$(srcdir)/markdown2.py" -x link-patterns --link-patterns-file markdown-urls'


# Create arguments for configure:
AC_ARG_WITH([guile],
  [AS_HELP_STRING([[--with-guile[=COMMAND] / --without-guile]],
    [require/disable guile; many tools use guile (default: auto-detect).])],
  [GUILE="$withval"])

AC_ARG_ENABLE([guile-readline],
  [AS_HELP_STRING([--enable-guile-readline / --disable-guile-readline],
    [require/disable readline support within guile (default: auto-detect)])])

AC_ARG_WITH([scsh],
  [AS_HELP_STRING([[--with-scsh[=COMMAND] / --without-scsh]],
    [require/disable support for scsh (default: auto-detect).])],
  [SCSH="$withval"])

AC_ARG_WITH([common-lisp],
  [AS_HELP_STRING([[--with-common-lisp[=DIR] / --without-common-lisp]],
    [require/disable Common Lisp library source code install to directory DIR (default: install to $(datadir)/common-lisp).])],
  [COMMON_LISP_LIB_DIR="$withval"])

AC_ARG_WITH([clisp],
  [AS_HELP_STRING([[--with-clisp[=COMMAND] / --without-clisp]],
    [require/disable support for clisp (default: auto-detect). This requires general Common Lisp support.  COMMAND sets CLISP])],
  [CLISP="$withval"])

AC_ARG_WITH([sbcl],
  [AS_HELP_STRING([[--with-sbcl[=COMMAND] / --without-sbcl]],
    [require/disable support for sbcl (default: auto-detect).])],
  [SBCL="$withval"])

AC_ARG_WITH([register-cl-source],
  [AS_HELP_STRING([[--with-register-cl-source[=COMMAND] / --without-register-cl-source]],
    [require/disable support for the utility to register Common Lisp source (default: auto-detect for register-common-lisp-source program in PATH).])],
  [REGISTER_COMMON_LISP_SOURCE="$withval"])

AC_ARG_WITH([unregister-cl-source],
  [AS_HELP_STRING([[--with-unregister-cl-source[=COMMAND] / --without-unregister-cl-source]],
    [require/disable support for unregistering Common Lisp source (default: auto-detect.  If register-cl-source is 'no', this is too)])],
  [UNREGISTER_COMMON_LISP_SOURCE="$withval"])

AC_ARG_WITH([markdown],
  [AS_HELP_STRING(
    [[--with-markdown[=COMMAND] | --without-markdown]],
    [require/forbid translating markdown into HTML (default: Use included markdown2 implementation, which uses Python).])],
  [MARKDOWN="$withval"])

# Other special environment variables/command-line variables
AC_ARG_VAR([BIN_ENV],
  [Command to run env (default: auto-detect, often /usr/bin/env)])
AC_ARG_VAR([EXPECT], [Command to run expect (default: auto-detect)])
AC_ARG_VAR([GUILE_SITE],
  [Guile site directory (default: auto-detect; often /usr/share/guile/site)])


# Sanity check all AC_ARG_WITH, AC_ARG_VAR, and AC_ARG_ENABLE variables
# so they don't begin with "-" or space.  Then we can use "test" without
# "x" prefixes, even on systems that aren't POSIX 2008.
# Many autoconf files have text of the form test "x$variable" because
# variable might begin with "-"; POSIX 2008 systems can handle this when
# there are <=3 arguments, but a non-compliant system could get it wrong.
m4_ifdef([AS_VAR_COPY], [
for input_variable in \
  with_guile GUILE \
  with_guile_readline \
  with_scsh SCSH \
  with_common_lisp COMMON_LISP_LIB_DIR \
  with_clisp CLISP \
  with_sbcl SBCL \
  with_register_cl_source REGISTER_COMMON_LISP_SOURCE \
  with_unregister_cl_source UNREGISTER_COMMON_LISP_SOURCE \
  with_markdown MARKDOWN \
  BIN_ENV EXPECT GUILE_SITE
do
  AS_VAR_COPY([received_value], [$input_variable])
  AS_CASE(["$received_value"],
    [[[-\ ]*]],
      [AC_MSG_ERROR([Input $input_variable begins with dash or space: $received_value])])
done
])

# If registering is forceably disabled, disable unregistering to match
AS_IF([test "$with_register_cl_source" = "no"],
  [with_unregister_cl_source=no])

# It doesn't make sense to provide a "useful" value for these:
AS_IF([is_useful "$enable_guile_readline"],
  [AC_MSG_ERROR([enable-guile-readline must be 'yes', 'no', or no value])])

# Sanity-check combinations of argument values.
AS_IF([test "$with_guile" = no && test "$with_common_lisp" = no],
  [AC_MSG_WARN([Both --without-guile and --without-common-lisp specified, little to do])])
AS_IF([test "$with_common_lisp" = no && test "$with_clisp" = yes],
  [AC_MSG_ERROR([clisp requires Common Lisp support])])
AS_IF([test "$with_common_lisp" = no && test "$with_sbcl" = yes],
  [AC_MSG_ERROR([sbcl requires Common Lisp support])])


# Setup basics
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_SED

AC_PATH_PROG([BIN_ENV], [env])
AS_IF([is_empty "$BIN_ENV"],
  [AC_MSG_ERROR([No executable "env" available.])])

# Is this a normal install, or a "make distcheck"?  We need to disable
# the tests in a "make distcheck" that won't work.
is_make_distcheck=no
AS_CASE([$prefix],
  [*/_inst],
    [AC_MSG_NOTICE([[Prefix ends in /_inst; this is a 'make distcheck'.]])
     is_make_distcheck=yes])
AM_CONDITIONAL([IS_MAKE_DISTCHECK], [is_enabled "$is_make_distcheck"])
AC_MSG_CHECKING([final decision IS_MAKE_DISTCHECK (running "make distcheck"?)])
AM_COND_IF([IS_MAKE_DISTCHECK], [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])

### GUILE ###

# For purposes of configuration, do we have a working guile?
AS_IF([is_permitted "$with_guile"],
  [AS_IF([is_useful "$GUILE"], [:], [AC_PATH_PROG([GUILE],[guile])])
   AS_IF([is_useful "$GUILE"],
    [AC_SUBST([GUILE])
     :])])
AM_CONDITIONAL([HAVE_GUILE], [is_useful "$GUILE"])
AC_MSG_CHECKING([final decision HAVE_GUILE])
AM_COND_IF([HAVE_GUILE], [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])

# If we have guile, configure it.
GUILE_READLINE_AVAILABLE=no
AM_COND_IF([HAVE_GUILE],
 [# Guile provides autoconf macros in guile.m4, but they require guile-config.
  # Sadly, guile-config doesn't come standard on all "guile" packages on all
  # distros, so using guile-config would make our package harder to install.
  # Instead, we implement these searches directly, making our package
  # much easier to install.
  # Since we aren't linking into guile, this isn't hard to do.

  # Determine Guile's "site" directory, where libraries are stored.
  # Guile's autoconf macro "GUILE_SITE_DIR" sets GUILE_SITE to the value of
  # the site directory, but as noted above, users often don't have
  # the guile autoconf macros installed.  In addition,
  # GUILE_SITE_DIR doesn't honor the $prefix value anyway, which causes
  # "make distcheck" to always fail, making GUILE_SITE_DIR problematic:
  #   http://lists.gnu.org/archive/html/guile-user/2009-01/msg00049.html
  #   http://lists.gnu.org/archive/html/guile-user/2009-01/msg00048.html
  # We use:
  # 1. GUILE_SITE if not empty.  Otherwise,
  # 2. If it's a normal install (not a "make distcheck"), and
  #    guile reports a non-empty value, use that value.  Otherwise,
  # 3. Use the value '${datarootdir}/guile/site'
  AS_IF([is_empty "$GUILE_SITE"],
   [AC_MSG_NOTICE([No GUILE_SITE value has been forceably set.])
    AM_COND_IF([IS_MAKE_DISTCHECK], [],
      [# Query the guile interpreter directly to find guile site directory
       AC_MSG_CHECKING([asking guile for its site directory])
       GUILE_SITE=`[$GUILE] -q -c "(display (%site-dir))"`
       AC_MSG_RESULT([$GUILE_SITE])])])
  AS_IF([is_empty "$GUILE_SITE"],
    [# GUILE_SITE *still* has no value.  We must be in a "make distcheck"
     # or we were unable to get a useful value from Guile.
     AC_MSG_NOTICE([[Setting GUILE_SITE using datarootdir (which uses prefix)]])
     GUILE_SITE='${datarootdir}/guile/site'])
  # Add spaces at end to make results line up in the usual situation:
  AC_MSG_CHECKING([[Guile site directory (GUILE_SITE)  ]])
  AC_MSG_RESULT([$GUILE_SITE])

  # Determine if "readline" is available in guile.
  AC_MSG_CHECKING([if (ice-9 readline) is available])
  AS_IF([is_permitted "$enable_guile_readline"],
   [[$GUILE] -q \
      -c "(use-modules (ice-9 readline)) (exit ((lambda () 0)))" \
      > /dev/null 2>&1
    GUILE_READLINE_AVAILABLE=$?
    AS_IF([test "$GUILE_READLINE_AVAILABLE" = "0"],
      [GUILE_READLINE_AVAILABLE=yes],
      [GUILE_READLINE_AVAILABLE=no])])
  AC_MSG_RESULT([$GUILE_READLINE_AVAILABLE])
  AS_IF([test "$GUILE_READLINE_AVAILABLE" = "no" && \
         test "$enable_guile_readline" = "yes"],
    [AC_MSG_ERROR([Guile readline required but unavailable.])])

  # Determine if guile can handle cond...else.  This is standard Scheme,
  # and chicken Scheme complains if you use cond...#t.  Sadly,
  # guile 1.6 doesn't support it.  So we'll try to use it; if it fails,
  # we will set PATCH_COND_ELSE to a program that fixes it.
  # Normally PATCH_COND_ELSE is ":", which is a no-op.
  AC_MSG_CHECKING([if (cond...else) is supported in guile])
  AS_IF([[$GUILE] -q \
      -c '(cond (#f (display "bad")) (else (display "good")))' \
      > /dev/null 2>&1],
    [AC_MSG_RESULT([yes])
     PATCH_COND_ELSE=':'],
    [AC_MSG_RESULT([no])
     PATCH_COND_ELSE='$(srcdir)/patch_cond_else'])
  AC_SUBST([PATCH_COND_ELSE])


  AS_IF([is_permitted "$with_scsh"],
    [AS_IF([is_useful "$SCSH"], [], [AC_PATH_PROG([SCSH],[scsh])])
     AS_IF([is_useful "$SCSH"],
      [AC_SUBST([SCSH])
       :])])
])
AC_SUBST([GUILE_READLINE_AVAILABLE])
AM_CONDITIONAL([HAVE_SCSH], [is_useful "$SCSH"])
AC_MSG_CHECKING([final decision HAVE_SCSH])
AM_COND_IF([HAVE_SCSH], [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])

AM_COND_IF([HAVE_GUILE], [],
  [# We do not have guile.
   AS_IF([test "$with_guile" = "yes"],
    [AC_MSG_ERROR([guile required but unavailable.])])
   AM_COND_IF([HAVE_SCSH],
    [AC_MSG_ERROR([guile unavailable yet scsh given forced value.])])])
AM_COND_IF([HAVE_SCSH], [],
  [AS_IF([test "$with_scsh" = "yes"],
    [AC_MSG_ERROR([scsh required but unavailable.])])])


### COMMON LISP ###

# Common Lisp by itself just installs to a directory, so we'll
# always do it if permitted to do so:
echo >&2
AS_IF([is_permitted "$with_common_lisp"],
 [with_common_lisp=yes
  AC_MSG_NOTICE([Installing Common Lisp's library source code into a directory.])
  AS_IF([is_useful "$COMMON_LISP_LIB_DIR"], [],
    [COMMON_LISP_LIB_DIR='$(datadir)/common-lisp'
     AS_IF([test "$prefix" = "/usr"], [],
       [AC_MSG_WARN([Prefix is not /usr; ensure ASDF configuration looks here.])])])
  AC_MSG_CHECKING([Common Lisp lib dir (COMMON_LISP_LIB_DIR)])
  AC_MSG_RESULT([$COMMON_LISP_LIB_DIR])
  AC_SUBST([COMMON_LISP_LIB_DIR])

  AS_IF([is_permitted "$with_register_cl_source"],
    [AS_IF([is_useful "$REGISTER_COMMON_LISP_SOURCE"], [], [AC_PATH_PROG([REGISTER_COMMON_LISP_SOURCE],[register-common-lisp-source])])
     AS_IF([is_useful "$REGISTER_COMMON_LISP_SOURCE"],
       [AC_SUBST([REGISTER_COMMON_LISP_SOURCE])
        :])])

  AS_IF([is_permitted "$with_unregister_cl_source"],
    [AS_IF([is_useful "$UNREGISTER_COMMON_LISP_SOURCE"], [], [AC_PATH_PROG([UNREGISTER_COMMON_LISP_SOURCE],[unregister-common-lisp-source])])
     AS_IF([is_useful "$UNREGISTER_COMMON_LISP_SOURCE"],
       [AC_SUBST([UNREGISTER_COMMON_LISP_SOURCE])
        :])])

  # We'll use LN_S to install Common Lisp ASDF files:
  AC_PROG_LN_S])
AM_CONDITIONAL([INSTALL_COMMON_LISP_LIB], [is_enabled "$with_common_lisp"])
AC_MSG_CHECKING([final decision INSTALL_COMMON_LISP_LIB])
AC_MSG_RESULT([$with_common_lisp])

AM_CONDITIONAL([HAVE_REGISTER_COMMON_LISP_SOURCE],
               [is_useful "$REGISTER_COMMON_LISP_SOURCE"])
AC_MSG_CHECKING([final decision HAVE_REGISTER_COMMON_LISP_SOURCE])
AM_COND_IF([HAVE_REGISTER_COMMON_LISP_SOURCE],
           [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])
AM_CONDITIONAL([HAVE_UNREGISTER_COMMON_LISP_SOURCE],
               [is_useful "$UNREGISTER_COMMON_LISP_SOURCE"])
AC_MSG_CHECKING([final decision HAVE_UNREGISTER_COMMON_LISP_SOURCE])
AM_COND_IF([HAVE_UNREGISTER_COMMON_LISP_SOURCE],
           [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])

# If Common Lisp won't be installed, clisp and sbcl possibilities are limited.
AM_COND_IF([INSTALL_COMMON_LISP_LIB], [],
 [AS_IF([is_no_or_empty "$with_clisp"],
    [with_clisp=no],
    [AC_MSG_ERROR([Common Lisp not available yet clisp required])])
  AS_IF([is_no_or_empty "$with_sbcl"],
    [with_sbcl=no],
    [AC_MSG_ERROR([Common Lisp not available yet sbcl required])])])

# Check clisp
have_clisp_working_asdf=no
announce_make_clisp_asdf=no
AS_IF([is_permitted "$with_clisp"],
  [AS_IF([is_useful "$CLISP"], [], [AC_PATH_PROG([CLISP],[clisp])])
   AS_IF([is_useful "$CLISP"],
    [AC_SUBST([CLISP])
     AC_MSG_CHECKING([if (require "asdf") is available in clisp])
     echo '(require "asdf")' > asdf-check.lisp
     [$CLISP] asdf-check.lisp > /dev/null 2>&1
     AS_IF([test "$?" = 0],
       [have_clisp_working_asdf=yes],
       [announce_make_clisp_asdf=yes])
     AC_MSG_RESULT([$have_clisp_working_asdf])
     rm -f asdf-check.lisp],
    [AS_IF([test "$with_clisp" = yes],
     [AC_MSG_ERROR([clisp required but not found])])])])
AM_CONDITIONAL([HAVE_CLISP], [is_enabled "$have_clisp_working_asdf"])
AC_MSG_CHECKING([final decision HAVE_CLISP])
AC_MSG_RESULT([$have_clisp_working_asdf])

# Check sbcl.
AS_IF([is_permitted "$with_sbcl"],
  [AS_IF([is_useful "$SBCL"], [], [AC_PATH_PROG([SBCL],[sbcl])])
   AS_IF([is_useful "$SBCL"],
         [AC_SUBST([SBCL])
          :])])
AM_CONDITIONAL([HAVE_SBCL], [is_useful "$SBCL"])
AC_MSG_CHECKING([final decision HAVE_SBCL])
AM_COND_IF([HAVE_SBCL], [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])

AM_COND_IF([HAVE_SBCL], [],
  [AS_IF([test "$with_sbcl" = "yes"],
    [AC_MSG_ERROR([sbcl required but unavailable.])])])



### Other stuff ###
echo >&2

# If users have not specified their own markdown processor,
# we'll try to use the pre-supplied markdown2 implementation.
# In that case, we'll look for python (which is required for markdown2).
# Markdown2 only requires a very old version of Python and it works with 3.
# Developers will need a more modern version of Python to use
# get-from-wiki, but get-from-wiki is a developer convenience
# (not a user command) so we won't worry about that here.
AS_IF([is_permitted "$with_markdown"],
  [AS_IF([is_useful "$MARKDOWN"],
    [AC_MSG_CHECKING([Markdown command])
     AC_MSG_RESULT([$MARKDOWN])],
    [MARKDOWN="$default_markdown_command"
     AC_MSG_CHECKING([default markdown command])
     AC_MSG_RESULT([$MARKDOWN])
     AM_PATH_PYTHON([2.4], [],
       [AS_IF([test "$with_markdown" = yes],
          [AC_MSG_ERROR([Python not found, and markdown2 required.])])
        with_markdown=no
        AC_MSG_WARN([Python not found, and markdown2 requires it. HTML generation disabled])])])])

AM_CONDITIONAL([HAVE_MARKDOWN], [is_permitted "$with_markdown"])
AM_COND_IF([HAVE_MARKDOWN],
  [AC_SUBST([MARKDOWN])
   :])
AC_MSG_CHECKING([final decision HAVE_MARKDOWN])
AM_COND_IF([HAVE_MARKDOWN], [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])


AM_COND_IF([HAVE_GUILE],
  [AC_PATH_PROG([EXPECT], [expect])
   AS_IF([is_empty "$EXPECT"],
     [echo >&2
      AC_MSG_WARN([[expect not found; please install expect, or many command-line tools will fail]])
      echo >&2
      # Set EXPECT to a plausible value, in case it's installed later
      # or a later PATH makes "expect" visible.
      # An empty value is *certain* to fail later.
      EXPECT="$BIN_ENV expect"])])


# Emit key warnings LAST, so users are more likely to notice them.
AM_COND_IF([HAVE_GUILE], [],
  [echo >&2
   AC_MSG_WARN([GUILE NOT AVAILABLE.  Tools implemented with guile will not be available.])])

AS_IF([test "$announce_make_clisp_asdf" = yes],
  [echo >&2
   AC_MSG_WARN([CLISP FOUND, but clisp cannot currently invoke ASDF.])
   AC_MSG_NOTICE([Thus, clisp support is currently disabled.])
   AC_MSG_NOTICE([Run 'make clisp-asdf' to configure clisp to use ASDF for this user.])])

echo >&2

# Perhaps check for: (more) programs, libraries, header files, types,
# structures, compiler characteristics, library functions, system services.

# Do final output.
AC_OUTPUT

