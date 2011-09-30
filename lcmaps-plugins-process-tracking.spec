Summary: Process tracking plugin for the LCMAPS authorization framework
Name: lcmaps-plugins-process-tracking
Version: 0.0.5
Release: 1%{?dist}
License: Public Domain
Group: System Environment/Libraries
# The tarball was created from Subversion using the following commands:
# svn co svn://t2.unl.edu/brian/lcmaps-plugin-process-tracking
# cd lcmaps-plugin-process-tracking
# ./bootstrap
# ./configure
# make dist
Source0: %{name}-%{version}.tar.gz

BuildRequires: lcmaps-interface

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
This plugin utilizes the Kernel proc connector interface to 
track the processes spawned by glexec.

%prep
%setup -q

%build

%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install
mv $RPM_BUILD_ROOT/%{_libdir}/lcmaps $RPM_BUILD_ROOT/%{_libdir}/modules
ln -s liblcmaps_process_tracking.so $RPM_BUILD_ROOT/%{_libdir}/modules/liblcmaps_process_tracking.so.0
ln -s liblcmaps_process_tracking.so.0 $RPM_BUILD_ROOT/%{_libdir}/modules/liblcmaps_process_tracking.so.0.0.0
rm $RPM_BUILD_ROOT/%{_libdir}/modules/liblcmaps_process_tracking.la
rm $RPM_BUILD_ROOT/%{_libdir}/modules/liblcmaps_process_tracking.a

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/modules/lcmaps_process_tracking.mod
%{_libdir}/modules/liblcmaps_process_tracking.so
%{_libdir}/modules/liblcmaps_process_tracking.so.0
%{_libdir}/modules/liblcmaps_process_tracking.so.0.0.0

%changelog
* Wed Sep 28 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.5-1
- Correctly call waitpid to avoid zombie.  A few code warning cleanups.

* Fri Sep 23 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.4-1
- Initial build of the process tracking plugin.

