#######################################################################
##
## Makefile.am for proc_police
##
#######################################################################

ACLOCAL_AMFLAGS = -I m4 -I src

# no-write-strings is done because lcmaps_log uses "char *" instead
# of "const char *", causing newer compilers to freak
AM_CFLAGS = \
        -Werror \
	-Wall \
	-Wp,-D_FORTIFY_SOURCE=2 \
        $(LCMAPS_CFLAGS)

AM_CXXFLAGS = \
        $(LCMAPS_CFLAGS) \
        -Wno-write-strings \
        -Werror \
	-Wall \
	-Wp,-D_FORTIFY_SOURCE=2 \
        $(CXX0X_CFLAGS)

EXTRA_DIST = bootstrap lcmaps-plugins-process-tracking.spec

plugindir = $(MODULEDIR)
plugin_LTLIBRARIES = \
        liblcmaps_process_tracking.la
liblcmaps_process_tracking_la_SOURCES = \
	src/lcmaps_proc_tracking.c

liblcmaps_process_tracking_la_LDFLAGS = -avoid-version

progdatadir = $(datadir)/lcmaps-plugins-process-tracking
progdata_PROGRAMS = process-tracking

process_tracking_SOURCES = \
	src/proc_keeper_main.cxx \
	src/proc_keeper.h \
	src/proc_keeper.cxx \
	src/proc_police.c \
	src/proc_police.h

install-data-hook:
	( \
	cd $(DESTDIR)$(plugindir); \
	for mod in process_tracking; do \
	    rm -f lcmaps_$$mod.mod; \
	    ln -s liblcmaps_$$mod.so.0.0.0 lcmaps_$$mod.mod; \
	done \
	)

