INCLUDES =						\
	-I$(top_srcdir) 				\
	$(RCD_CFLAGS)					\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DMODULEDIR=\""$(rcd_moduledir)"\"		\
	-DSHAREDIR=\""$(datadir)/rcd"\"			\
	-DG_LOG_DOMAIN=\"rcd\"				\
	-Wall

noinst_PROGRAMS = rcd

rcd_SOURCES = 			\
	rcd-auth.h		\
	rcd-auth.c		\
	rcd-identity.h		\
	rcd-identity.c		\
	rcd-module.c		\
	rcd-module.h		\
	rcd-query.h		\
	rcd-query.c		\
	rcd-rpc.c		\
	rcd-rpc.h		\
	rcd-rpc-system.c	\
	rcd-rpc-system.h	\
	rcd.c

rcd_LDADD =	\
	$(RCD_LIBS)

rcd_moduledir = $(libdir)/rcd
rcd_module_LTLIBRARIES = librcd-sample.la

librcd_sample_la_SOURCES =	\
	rcd-rpc-sample.c	\
	rcd-rpc-sample.h

librcd_sample_la_LDFLAGS = -module -avoid-version