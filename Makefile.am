SUBDIRS = src

passwddir = $(sysconfdir)/ximian
initdir = $(sysconfdir)/init.d
logrotatedir = $(sysconfdir)/logrotate.d

certdir = $(datadir)/rcd
cert_DATA = rcd.pem

cadir = $(datadir)/rcd/ca
ca_DATA = rcd-ca-bundle.pem

gpgdir = $(datadir)/rcd
gpg_DATA = rcd.gpg

man_MANS = rcd.8 rcd.conf.5

EXTRA_DIST = rcd.passwd rcd.init rcd.logrotate $(cert_DATA) $(ca_DATA) $(gpg_DATA) $(man_MANS)

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

	$(INSTALL_DATA) -m 0755 $(srcdir)/rcd.init $(DESTDIR)$(initdir)/rcd;

	if test '!' -d $(DESTDIR)$(logrotatedir); then \
		$(mkinstalldirs) $(DESTDIR)$(logrotatedir); \
		chmod 0755 $(DESTDIR)$(logrotatedir); \
	fi

	$(INSTALL_DATA) -m 0755 $(srcdir)/rcd.logrotate $(DESTDIR)$(logrotatedir)/rcd;

