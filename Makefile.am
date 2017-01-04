DISTCLEANFILES = \
	journal-triggerd.1 \
	journal-triggerd.service \
	index.html

ACLOCAL_AMFLAGS = -I m4

rulesdir=@rulesdir@
servicedir=@servicedir@

if USE_GIT_VERSION
_VERSION = `git describe --abbrev=4 --dirty`
DEFS += -DGIT_VERSION=\"$(_VERSION)\"
else
_VERSION = $(PACKAGE_VERSION)
endif

bin_PROGRAMS = journal-triggerd

AM_CFLAGS = \
	-g \
	-DDOCDIR='"$(docdir)"' \
	${WARNING_CFLAGS}

journal_triggerd_CFLAGS = ${AM_CFLAGS} @GLIB2_CFLAGS@ @JOURNAL_CFLAGS@
journal_triggerd_LDADD = @GLIB2_LIBS@ @JOURNAL_LIBS@
journal_triggerd_SOURCES = \
	main.c \
	macros.h

dist_man_MANS = journal-triggerd.1
dist_doc_DATA = index.html \
				HISTORY \
				AUTHORS \
				COPYING \
				README.md

service_DATA = journal-triggerd.service

EXTRA_DIST = \
	journal-triggerd.pod \
	journal-triggerd.service.in

journal-triggerd.1: journal-triggerd.pod
	$(AM_V_GEN)pod2man --center='Runs trigger on journal messages' --section=1 \
		--release=$(_VERSION) journal-triggerd.pod journal-triggerd.1

index.html: journal-triggerd.1
	$(AM_V_GEN)groff -T html -man journal-triggerd.1 > index.html

install-data-hook:
	$(MKDIR_P) "$(DESTDIR)$(docdir)/html"
	mv "$(DESTDIR)$(docdir)/index.html" "$(DESTDIR)$(docdir)/html/"
	$(MKDIR_P) "$(DESTDIR)$(rulesdir)"

journal-triggerd.service: $(srcdir)/journal-triggerd.service.in Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
		test -f ./$@.in || srcdir=$(srcdir)/; \
		sed -e 's|@bindir[@]|$(bindir)|g' $${srcdir}$@.in >$@.tmp
	mv $@.tmp $@
