AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. $(CPPUNIT_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument
LDADD = ../../tsk/libtsk.la $(CPPUNIT_LIBS)
LDFLAGS = -static

TESTS = test_exfat_dentry_set

check_PROGRAMS = test_exfat_dentry_set

test_exfat_dentry_set_SOURCES = test_exfat_main.cpp \
	exfat_dentry_set_test.cpp exfat_dentry_set_test.h \
	exfat_synthetic_image.cpp exfat_synthetic_image.h

MAINTAINERCLEANFILES = Makefile.in

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
