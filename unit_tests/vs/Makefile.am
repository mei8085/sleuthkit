AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. $(CPPUNIT_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument
LDADD = ../../tsk/libtsk.la $(CPPUNIT_LIBS)
LDFLAGS = -static

TESTS = test_vs_partition

check_PROGRAMS = test_vs_partition

test_vs_partition_SOURCES = test_vs_partition_main.cpp \
	vs_partition_boundary_test.cpp vs_partition_boundary_test.h \
	vs_synthetic_image.cpp vs_synthetic_image.h

MAINTAINERCLEANFILES = Makefile.in

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
