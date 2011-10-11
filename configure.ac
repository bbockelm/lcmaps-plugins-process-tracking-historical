
AC_INIT(lcmaps-plugins-process-tracking,0.0.6,bbockelm@cse.unl.edu)
AC_PREREQ(2.57)
AM_INIT_AUTOMAKE([1.9 no-define foreign])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_CXX

AX_CXX_HEADER_UNORDERED_MAP

# Check LCMAPS location
AC_LCMAPS_INTERFACE([basic])
if test "x$have_lcmaps_interface" = "xno" ; then
    AC_MSG_FAILURE(["no LCMAPS interface found"])
fi

dnl allow the setting of a different path for the plug-ins
dnl Makefiles should set the plugindir to $MODULEDIR.
AC_ARG_WITH([moduledir],
  [AS_HELP_STRING([--with-moduledir=path],
    [Specify the install location of the plug-ins])],
[
	AC_SUBST([MODULEDIR], [$withval])
],
[
	AC_SUBST([MODULEDIR], ['${libdir}/lcmaps'])
])

AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

