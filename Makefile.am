SUBDIRS = libredcarpet src

passwddir = $(sysconfdir)/ximian
passwd_DATA = rc-passwd

initdir = $(sysconfdir)/init.d
init_DATA = rcd

certdir = $(datadir)/rcd
cert_DATA = rcd.pem

EXTRA_DIST = $(passwd_DATA) $(init_DATA) $(cert_DATA) rcd.8 

man_MANS = rcd.8

install-data-hook:
	chmod 0755 $(DESTDIR)$(initdir)/$(init_DATA)
	chmod 0600 $(DESTDIR)$(passwddir)/$(passwd_DATA)
	-chown root $(DESTDIR)$(passwddir)/$(passwd_DATA)

