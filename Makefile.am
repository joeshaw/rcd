SUBDIRS = src

passwddir = $(sysconfdir)/ximian
noinst_DATA = rc-passwd

initdir = $(sysconfdir)/init.d
init_DATA = rcd

certdir = $(datadir)/rcd
cert_DATA = rcd.pem

gpgdir = $(datadir)/rcd
gpg_DATA = rcd.gpg

man_MANS = rcd.8

EXTRA_DIST = $(noinst_DATA) $(init_DATA) $(cert_DATA) $(gpg_DATA) $(man_MANS)

install-data-hook: rc-passwd
	if test '!' -d $(DESTDIR)$(passwddir); then \
		$(mkinstalldirs) $(DESTDIR)$(passwddir); \
		chmod 0755 $(DESTDIR)$(passwddir); \
	fi

	if test '!' -f $(DESTDIR)$(passwddir)/rc-passwd; then \
		$(INSTALL_DATA) rc-passwd $(DESTDIR)$(passwddir)/rc-passwd; \
		chmod 0600 $(DESTDIR)$(passwddir)/rc-passwd; \
		-chown root $(DESTDIR)$(passwddir)/rc-passwd; \
	fi
	$(INSTALL_DATA) rc-passwd $(DESTDIR)$(passwddir)/rc-passwd.default

	chmod 0755 $(DESTDIR)$(initdir)/$(init_DATA)

