INCLUDES =						\
	-I$(top_srcdir) 				\
	$(RCD_CFLAGS)					\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-DSHAREDIR=\""$(datadir)/rcd"\"			\
	-DG_LOG_DOMAIN=\"rcd\"				\
	-Wall

noinst_PROGRAMS = rcd

rcd_SOURCES = 			\
	rcd-auth.h		\
	rcd-auth.c		\
	rcd-identity.h		\
	rcd-identity.c		\
	rcd-query.h		\
	rcd-query.c		\
	rcd.c

rcd_LDADD =	\
	$(RCD_LIBS)

