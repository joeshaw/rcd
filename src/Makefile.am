INCLUDES =						\
	-I$(top_srcdir) 				\
	$(RCD_CFLAGS)					\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DSHAREDIR=\""$(datadir)/rcd"\"			\
	-DG_LOG_DOMAIN=\"rcd\"				\
	-Wall

noinst_PROGRAMS = rcd

rcd_SOURCES = 		\
	rcd-query.h	\
	rcd-query.c	\
	rcd.c

rcd_LDADD =	\
	$(RCD_LIBS)

