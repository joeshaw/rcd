SUBDIRS = src

passwddir = $(sysconfdir)/ximian
passwd_DATA = rc-passwd

initdir = $(sysconfdir)/init.d
init_DATA = rcd

EXTRA_DIST = $(passwd_DATA) $(init_DATA) rcd.8

man_MANS = rcd.8

install-data-hook:
	chmod 0755 $(DESTDIR)$(initdir)/$(init_DATA)