SUBDIRS = src

passwddir = $(sysconfdir)/ximian
initdir = $(sysconfdir)/init.d
logrotatedir = $(sysconfdir)/logrotate.d

certdir = $(datadir)/rcd
cert_DATA = rcd.pem

gpgdir = $(datadir)/rcd
gpg_DATA = rcd.gpg

man_MANS = rcd.8 rcd.config.5

EXTRA_DIST = rc-passwd $(cert_DATA) $(gpg_DATA) $(man_MANS)

install-data-hook:
	if test '!' -d $(DESTDIR)$(passwddir); then \
		$(mkinstalldirs) $(DESTDIR)$(passwddir); \
		chmod 0755 $(DESTDIR)$(passwddir); \
	fi

	if test '!' -f $(DESTDIR)$(passwddir)/rc-passwd; then \
		$(INSTALL_DATA) $(srcdir)/rc-passwd $(DESTDIR)$(passwddir)/rc-passwd; \
	fi
	chmod 0600 $(DESTDIR)$(passwddir)/rc-passwd
	-chown root $(DESTDIR)$(passwddir)/rc-passwd

	$(INSTALL_DATA) $(srcdir)/rc-passwd $(DESTDIR)$(passwddir)/rc-passwd.default

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

