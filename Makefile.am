#######################################################################
##
## Makefile.am for proc_police
##
#######################################################################

ACLOCAL_AMFLAGS = -I m4

# no-write-strings is done because lcmaps_log uses "char *" instead
# of "const char *", causing newer compilers to freak
AM_CPPFLAGS = \
        $(CXX0X_CFLAGS) \
        $(LCMAPS_CFLAGS) \
        -Wno-write-strings \
        -I$(top_srcdir)/interface

EXTRA_DIST = bootstrap lcmaps-plugins-process-tracking.spec

plugindir = $(MODULEDIR)
plugin_LTLIBRARIES = \
        liblcmaps_process_tracking.la
liblcmaps_process_tracking_la_SOURCES = \
	src/lcmaps_proc_tracking.c \
	src/proc_keeper.cxx \
	src/proc_keeper.h \
	src/proc_police.c \
	src/proc_police.h

liblcmaps_process_tracking_la_LDFLAGS = -avoid-version

install-data-hook:
	( \
	cd $(DESTDIR)$(plugindir); \
	for mod in process_tracking; do \
	    rm -f lcmaps_$$mod.mod; \
	    ln -s liblcmaps_$$mod.so.0.0.0 lcmaps_$$mod.mod; \
	done \
	)

