rcd_moduledir = $(libdir)/rcd/modules

INCLUDES =						\
	-I ../ 				\
	$(RCD_CFLAGS)					\
	$(YAST_CFLAGS)					\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DMODULEDIR=\""$(rcd_moduledir)"\"		\
	-DSHAREDIR=\""$(datadir)/rcd"\"			\
	-DSYSCONFDIR=\""$(sysconfdir)/ximian"\"		\
	-Wall

rcd_module_LTLIBRARIES = \
	librcd-you.la

librcd_you_la_SOURCES =	\
	rc-you-file.c		\
	rc-you-file.h		\
	rc-you-package.c	\
	rc-you-package.h	\
	rc-you-patch.c		\
	rc-you-patch.h		\
	rc-world-you.c		\
	rc-world-you.h		\
	rc-you-transaction.c	\
	rc-you-transaction.h	\
	you-util.c		\
	you-util.h		\
	wrapper.cc		\
	wrapper.h		\
	you.c

librcd_you_la_LDFLAGS = -module -avoid-version $(YAST_LIBS)

