Summary: a c++ implementation of an OpenID decentralized identity system
Name: libopkele
Version: 2.0.4
Release: 1
License: BSD
URL: http://kin.klever.net/libopkele/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: expat-devel
BuildRequires: gcc-c++
BuildRequires: libcurl-devel
BuildRequires: libtidy-devel
BuildRequires: openssl-devel

%description
libopkele is a c++ implementation of an OpenID decentralized identity system.
It provides OpenID protocol handling, leaving authentication and user
interaction to the implementor.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libopkele.a
%{_libdir}/libopkele.la
%{_libdir}/libopkele.so
%{_libdir}/libopkele.so.3
%{_libdir}/libopkele.so.3.0.0
%{_libdir}/pkgconfig/libopkele.pc

%package devel
Summary: Development headers for libopkele
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
libopkele is a c++ implementation of an OpenID decentralized identity system.
It provides OpenID protocol handling, leaving authentication and user
interaction to the implementor.

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/opkele
%{_includedir}/opkele/acconfig.h
%{_includedir}/opkele/association.h
%{_includedir}/opkele/ax.h
%{_includedir}/opkele/basic_op.h
%{_includedir}/opkele/basic_rp.h
%{_includedir}/opkele/exception.h
%{_includedir}/opkele/extension.h
%{_includedir}/opkele/extension_chain.h
%{_includedir}/opkele/iterator.h
%{_includedir}/opkele/oauth_ext.h
%{_includedir}/opkele/opkele-config.h
%{_includedir}/opkele/prequeue_rp.h
%{_includedir}/opkele/sreg.h
%{_includedir}/opkele/tr1-mem.h
%{_includedir}/opkele/types.h
%{_includedir}/opkele/uris.h
%{_includedir}/opkele/util.h
%{_includedir}/opkele/verify_op.h
