SUBDIRS = src

passwddir = $(sysconfdir)/ximian
initdir = $(sysconfdir)/rc.d/init.d
logrotatedir = $(sysconfdir)/logrotate.d

certdir = $(datadir)/rcd
cert_DATA = rcd.pem rcd-ca-bundle.pem

gpgdir = $(datadir)/rcd
gpg_DATA = rcd.gpg

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = rcd.pc

man_MANS = rcd.8 rcd.conf.5

EXTRA_DIST = rcd.init.redhat.in rcd.init.suse.in rcd.init.debian.in \
	     rcd.init.solaris.in rcd.pc.in rcd.passwd rcd.logrotate \
	     $(cert_DATA) $(gpg_DATA) $(man_MANS)

if INIT_REDHAT
init_file = rcd.init.redhat
endif

if INIT_SUSE
init_file = rcd.init.suse
endif

if INIT_DEBIAN
init_file = rcd.init.debian
endif

if INIT_SOLARIS
init_file = rcd.init.solaris
endif

install-data-hook:
	if test '!' -d $(DESTDIR)$(passwddir); then \
		$(mkinstalldirs) $(DESTDIR)$(passwddir); \
		chmod 0755 $(DESTDIR)$(passwddir); \
	fi

	if test '!' -f $(DESTDIR)$(passwddir)/rcd.passwd; then \
		$(INSTALL_DATA) $(srcdir)/rcd.passwd $(DESTDIR)$(passwddir)/rcd.passwd; \
	fi
	chmod 0600 $(DESTDIR)$(passwddir)/rcd.passwd
	-chown root $(DESTDIR)$(passwddir)/rcd.passwd

	$(INSTALL_DATA) $(srcdir)/rcd.passwd $(DESTDIR)$(passwddir)/rcd.passwd.default



	if test '!' -d $(DESTDIR)$(initdir); then \
		$(mkinstalldirs) $(DESTDIR)$(initdir); \
		chmod 0755 $(DESTDIR)$(initdir); \
	fi

	$(INSTALL_DATA) -m 0755 $(srcdir)/$(init_file) $(DESTDIR)$(initdir)/rcd;

	if test '!' -d $(DESTDIR)$(logrotatedir); then \
		$(mkinstalldirs) $(DESTDIR)$(logrotatedir); \
		chmod 0755 $(DESTDIR)$(logrotatedir); \
	fi

	$(INSTALL_DATA) -m 0755 $(srcdir)/rcd.logrotate $(DESTDIR)$(logrotatedir)/rcd;

uninstall-hook:
	rm -f $(DESTDIR)$(passwddir)/rcd.passwd.default
	rm -f $(DESTDIR)$(initdir)/rcd
	rm -f $(DESTDIR)$(logrotatedir)/rcd
