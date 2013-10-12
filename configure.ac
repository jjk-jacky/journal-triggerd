#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([journal-triggerd], [0.2.0], [jjk@jjacky.com])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([-Wall -Werror foreign silent-rules])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_MKDIR_P
AC_PROG_CC

# Rules locations
AC_ARG_WITH([rulesdir],
            AC_HELP_STRING([--with-rulesdir=DIR], [Directory for .rule files]),
            [],
            [with_rulesdir=/etc/journal-triggerd.rules])

# service file location
AC_ARG_WITH([servicedir],
            AC_HELP_STRING([--with-systemd-servicedir=DIR], [Directory for .service file]),
            [],
            [with_servicedir=/usr/lib/systemd/system])

# Option to use git version
AC_ARG_ENABLE([git-version],
              AS_HELP_STRING([--enable-git-version], [enable the use of git
                              version]),
                              [wantgitver=$enableval], [wantgitver=no])

# Enable extra compiler warning flags
AC_ARG_ENABLE([warning-flags],
              AS_HELP_STRING([--enable-warning-flags], [enable extra compiler
                              warning flags]),
                              [warningflags=$enableval], [warningflags=no])

# Checks for libraries.
PKG_CHECK_MODULES(JOURNAL, [libsystemd-journal], ,
                  AC_MSG_ERROR([libsystemd-journal is required]))
PKG_CHECK_MODULES(GLIB2, [glib-2.0], ,
                  AC_MSG_ERROR([glib2 is required]))

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h strings.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp strchr strerror strncasecmp])

# Define constant
AC_DEFINE_UNQUOTED([RULES_PATH], ["$with_rulesdir"], [Rules dir])

# git version
AC_MSG_CHECKING([if git version must be used])
if test "x$wantgitver" = "xyes"; then
    AC_MSG_RESULT([yes])
    AC_CHECK_PROGS([GIT], [git])
    if test "x$GIT" = "x"; then
        AC_MSG_ERROR([Cannot use git version: git not found])
    fi
    AC_CHECK_FILE([.git/], hasgitdir=yes)
    if test "x$hasgitdir" = "xyes"; then
        usegitver=yes
        gitver=-git
        AC_DEFINE([USE_GIT_VERSION], , [Use GIT version])
    else
        AC_MSG_ERROR([Cannot use git version: .git not found])
    fi
else
    AC_MSG_RESULT([no])
    usegitver=no
    gitver=
fi
AM_CONDITIONAL(USE_GIT_VERSION, test "x$usegitver" = "xyes")

# warning flags
WARNING_CFLAGS="-Wall"
AC_MSG_CHECKING([for extra compiler warning flags])
if test "x$warningflags" = "xyes"; then
    AC_MSG_RESULT([yes])
    CFLAGS_ADD([-Wextra], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wshadow], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wpointer-arith], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wcast-align], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wwrite-strings], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wmissing-prototypes], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wmissing-declarations], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wredundant-decls], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wnested-externs], [WARNING_CFLAGS])
    CFLAGS_ADD([-Winline], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wno-long-long], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wuninitialized], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wconversion], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wstrict-prototypes], [WARNING_CFLAGS])

    CFLAGS_ADD([-Wclobbered], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wempty-body], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wfloat-equal], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wformat-nonliteral], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wformat-security], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wignored-qualifiers], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wlogical-op], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wmissing-field-initializers], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wmissing-parameter-type], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wold-style-declaration], [WARNING_CFLAGS])
    CFLAGS_ADD([-Woverride-init], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wsign-compare], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wstrict-aliasing], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wstrict-overflow=5], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wtype-limits], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wunused-but-set-parameter], [WARNING_CFLAGS])
    CFLAGS_ADD([-Wunused-parameter], [WARNING_CFLAGS])
else
    AC_MSG_RESULT([no])
fi

AC_SUBST([rulesdir], [$with_rulesdir])
AC_SUBST([servicedir], [$with_servicedir])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
AC_MSG_RESULT([
        ${PACKAGE} version ${PACKAGE_VERSION}

 Build information:
    source code location        : ${srcdir}
    prefix                      : ${prefix}
    service file location       : ${with_servicedir}
    rules location              : ${with_rulesdir}

 Install paths:
    binaries                    : $(eval echo $(eval echo ${bindir}))
    documentation               : $(eval echo $(eval echo ${docdir}))
    man pages                   : $(eval echo $(eval echo ${mandir}))
])
