
AC_INIT(lcmaps-plugins-process-tracking,0.0.5,bbockelm@cse.unl.edu)
AC_PREREQ(2.57)
AM_INIT_AUTOMAKE([1.9 no-define foreign])

AC_PROG_LIBTOOL
AC_PROG_CXX

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

