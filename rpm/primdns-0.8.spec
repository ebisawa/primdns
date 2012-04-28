Name: primdns
Version: 0.8
Release: 1
Group: System Environment/Daemons
Vendor: Satoshi Ebisawa <ebisawa@gmail.com>
Packager: Satoshi Ebisawa <ebisawa@gmail.com>
URL: http://github.com/ebisawa/primdns
License: BSD
Summary: A simple DNS contents server
Source: http://github.com/ebisawa/primdns/tarball/v0.8
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%description

%prep
if [ -z "$RPM_BUILD_ROOT" -o "$RPM_BUILD_ROOT" = "/" ]; then
    exit 1
fi
mkdir -p $RPM_BUILD_ROOT
%setup -n ebisawa-primdns-379ffd9

%build
./configure --prefix=$RPM_BUILD_ROOT/usr --sysconfdir=$RPM_BUILD_ROOT/etc/primdns
make

%install
make install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/sbin/primd
/usr/sbin/primdns-axfr
/usr/sbin/primdns-makedb
/usr/sbin/primdns-updatezone
%config(noreplace) /etc/primdns/0.0.127.in-addr.arpa.zone
%config(noreplace) /etc/primdns/localhost.tiny
%config(noreplace) /etc/primdns/localhost.zone
%config(noreplace) /etc/primdns/primd.conf
