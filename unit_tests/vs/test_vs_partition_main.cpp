/*
 * test_vs_partition_main.cpp
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 *
 * CppUnit text runner for the partition boundary unit tests.
 */

#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>

int
main(int, char **)
{
    CppUnit::Test *suite =
        CppUnit::TestFactoryRegistry::getRegistry().makeTest();

    CppUnit::TextUi::TestRunner runner;
    runner.addTest(suite);
    runner.setOutputter(new CppUnit::CompilerOutputter(&runner.result(),
            std::cerr));

    bool wasSuccessful = runner.run();
    return wasSuccessful ? 0 : 1;
}
