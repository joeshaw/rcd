INCLUDES =						\
	-I$(top_srcdir) 				\
	$(RCD_CFLAGS)					\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DMODULEDIR=\""$(rcd_moduledir)"\"		\
	-DSHAREDIR=\""$(datadir)/rcd"\"			\
	-DSYSCONFDIR=\""$(sysconfdir)/ximian"\"		\
	-DG_LOG_DOMAIN=\"rcd\"				\
	-Wall

sbin_PROGRAMS = rcd

BUILT_SOURCES =			\
	rcd-marshal.h		\
	rcd-marshal.c

rcd_SOURCES = 			\
	gnome-config.c		\
	gnome-config.h		\
	parse-path.cP		\
	rcd-marshal.c		\
	rcd-marshal.h		\
	rcd-about.c		\
	rcd-about.h		\
	rcd-cache.c		\
	rcd-cache.h		\
	rcd-expire.c		\
	rcd-expire.h		\
	rcd-fetch.c		\
	rcd-fetch.h		\
	rcd-heartbeat.c		\
	rcd-heartbeat.h		\
	rcd-identity.c		\
	rcd-identity.h		\
	rcd-license.c		\
	rcd-license.h		\
	rcd-log.c		\
	rcd-log.h		\
	rcd-log-entry.c		\
	rcd-log-entry.h		\
	rcd-mirror.c		\
	rcd-mirror.h		\
	rcd-module.c		\
	rcd-module.h		\
	rcd-news.c		\
	rcd-news.h		\
	rcd-options.c		\
	rcd-options.h		\
	rcd-package-locks.c	\
	rcd-package-locks.h	\
	rcd-pending.c		\
	rcd-pending.h		\
	rcd-prefs.c		\
	rcd-prefs.h		\
	rcd-privileges.c	\
	rcd-privileges.h	\
	rcd-query.c		\
	rcd-query.h		\
	rcd-query-packages.c	\
	rcd-query-packages.h	\
	rcd-recurring.c		\
	rcd-recurring.h		\
	rcd-rpc.c		\
	rcd-rpc.h		\
	rcd-rpc-license.c	\
	rcd-rpc-license.h	\
	rcd-rpc-log.c		\
	rcd-rpc-log.h		\
	rcd-rpc-mirror.c	\
	rcd-rpc-mirror.h	\
	rcd-rpc-news.c		\
	rcd-rpc-news.h		\
	rcd-rpc-packsys.c	\
	rcd-rpc-packsys.h	\
	rcd-rpc-prefs.c		\
	rcd-rpc-prefs.h		\
	rcd-rpc-system.c	\
	rcd-rpc-system.h	\
	rcd-rpc-users.c		\
	rcd-rpc-users.h		\
	rcd-rpc-util.c		\
	rcd-rpc-util.h		\
	rcd-shutdown.c		\
	rcd-shutdown.h		\
	rcd-subscriptions.c	\
	rcd-subscriptions.h	\
	rcd-transaction.c	\
	rcd-transaction.h	\
	rcd-transfer.c		\
	rcd-transfer.h		\
	rcd-transfer-file.c	\
	rcd-transfer-file.h	\
	rcd-transfer-http.c	\
	rcd-transfer-http.h	\
	rcd-transfer-pool.c	\
	rcd-transfer-pool.h	\
	rcd-unix-server.c	\
	rcd-unix-server.h	\
	rcd-xmlrpc.c		\
	rcd-xmlrpc.h		\
	rcd.c

rcd_LDADD =	\
	$(LINK_BEGIN) $(RCD_LIBS) $(LINK_END) $(SHARED_ONLY)

rcd$(EXEEXT): $(rcd_OBJECTS) $(rcd_DEPENDENCIES)
	@rm -f rcd$(EXEEXT)
	$(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(rcd_LDFLAGS) $(rcd_OBJECTS) $(rcd_LDADD) $(LIBS)

rcdincludedir = $(includedir)/rcd
rcdinclude_HEADERS = 		\
	rcd-about.h		\
	rcd-cache.h		\
	rcd-heartbeat.h		\
	rcd-identity.h		\
	rcd-module.h 		\
	rcd-pending.h		\
	rcd-prefs.h		\
	rcd-privileges.h	\
	rcd-query.h		\
	rcd-recurring.h		\
	rcd-rpc.h		\
	rcd-rpc-prefs.h		\
	rcd-rpc-util.h		\
	rcd-shutdown.h		\
	rcd-transfer.h		\
	rcd-transfer-file.h	\
	rcd-transfer-http.h \
	rcd-xmlrpc.h

rcd_moduledir = $(libdir)/rcd/modules
rcd_module_LTLIBRARIES = 	\
	librcd-sample.la	\
	librcd-autopull.la

rcd_buddydir = $(datadir)/rcd
rcd_buddy_DATA = 		\
	rcd-buddy		\
	rcd-buddy-cmds

EXTRA_DIST =			\
	rcd-marshal.list	\
	rcd-buddy		\
	rcd-buddy-cmds

librcd_sample_la_SOURCES =	\
	rcd-rpc-sample.c	\
	rcd-rpc-sample.h

librcd_autopull_la_SOURCES =	\
	rcd-autopull.c

librcd_sample_la_LDFLAGS = -module -avoid-version
librcd_autopull_la_LDFLAGS = -module -avoid-version

###
### Deal with auto-generating the signal marshallers
###

rcd-marshal.h: rcd-marshal.list
	cd $(srcdir) \
	&& glib-genmarshal --prefix=rcd_marshal rcd-marshal.list --header >> xgen-gmh \
	&& (cmp -s xgen-gmh rcd-marshal.h || cp xgen-gmh rcd-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

rcd-marshal.c: rcd-marshal.list
	cd $(srcdir) \
	&& glib-genmarshal --prefix=rcd_marshal rcd-marshal.list --body >> xgen-gmc \
	&& (cmp -s xgen-gmc rcd-marshal.c || cp xgen-gmc rcd-marshal.c) \
	&& rm -f xgen-gmc xgen-gmc~

clean-local:
	rm -f rcd-marshal.c rcd-marshal.h
