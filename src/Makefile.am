INCLUDES =						\
	-I$(top_srcdir) 				\
	$(RCD_CFLAGS)					\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DMODULEDIR=\""$(rcd_moduledir)"\"		\
	-DSHAREDIR=\""$(datadir)/rcd"\"			\
	-DG_LOG_DOMAIN=\"rcd\"				\
	-Wall

noinst_PROGRAMS = rcd

BUILT_SOURCES =			\
	rcd-marshal.h		\
	rcd-marshal.c

rcd_SOURCES = 			\
	rcd-marshal.h		\
	rcd-marshal.c		\
	rcd-auth.h		\
	rcd-auth.c		\
	rcd-cache.h		\
	rcd-cache.c		\
	rcd-fetch.h		\
	rcd-fetch.c		\
	rcd-identity.h		\
	rcd-identity.c		\
	rcd-module.c		\
	rcd-module.h		\
	rcd-prefs.h		\
	rcd-prefs.c		\
	rcd-query.h		\
	rcd-query.c		\
	rcd-rpc.c		\
	rcd-rpc.h		\
	rcd-rpc-packsys.c	\
	rcd-rpc-packsys.h	\
	rcd-rpc-system.c	\
	rcd-rpc-system.h	\
	rcd-transfer.h		\
	rcd-transfer.c		\
	rcd-rpc-util.c		\
	rcd-rpc-util.h		\
	rcd-unix-server.c	\
	rcd-unix-server.h	\
	rcd.c

rcd_LDADD =	\
	$(RCD_LIBS)

rcd_moduledir = $(libdir)/rcd
rcd_module_LTLIBRARIES = librcd-sample.la

EXTRA_DIST =			\
	rcd-marshal.list

librcd_sample_la_SOURCES =	\
	rcd-rpc-sample.c	\
	rcd-rpc-sample.h

librcd_sample_la_LDFLAGS = -module -avoid-version

###
### Deal with auto-generating the signal marshallers
###

rcd-marshal.h: stamp-rcd-marshal.h
	@true   

rcd-marshal.c: stamp-rcd-marshal.c
	@true

stamp-rcd-marshal.h: rcd-marshal.list
	cd $(srcdir) \
	&& glib-genmarshal --prefix=rcd_marshal rcd-marshal.list --header >> xgen-gmh \
	&& (cmp -s xgen-gmh rcd-marshal.h || cp xgen-gmh rcd-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

stamp-rcd-marshal.c: rcd-marshal.list
	cd $(srcdir) \
	&& glib-genmarshal --prefix=rcd_marshal rcd-marshal.list --body >> xgen-gmc \
	&& (cmp -s xgen-gmc rcd-marshal.c || cp xgen-gmc rcd-marshal.c) \
	&& rm -f xgen-gmc xgen-gmc~

