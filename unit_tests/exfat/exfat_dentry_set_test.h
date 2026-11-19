/*
 * exfat_dentry_set_test.h
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef EXFAT_DENTRY_SET_TEST_H_
#define EXFAT_DENTRY_SET_TEST_H_

#include <cppunit/extensions/HelperMacros.h>

class ExfatDentrySetTest : public CppUnit::TestFixture
{
    CPPUNIT_TEST_SUITE(ExfatDentrySetTest);
    CPPUNIT_TEST(testCompleteSetIsVerified);
    CPPUNIT_TEST(testChecksumMismatchIsFlagged);
    CPPUNIT_TEST(testDeletedSetIsRecoverable);
    CPPUNIT_TEST(testDeletedSetWithBadChecksumIsUnconfirmed);
    CPPUNIT_TEST(testMissingNameEntryDoesNotStealNextFile);
    CPPUNIT_TEST(testMissingStreamDoesNotStealNextFile);
    CPPUNIT_TEST(testOutOfOrderEntriesDoNotJoinSet);
    CPPUNIT_TEST(testTruncatedAtEndOfDirectory);
    CPPUNIT_TEST(testOrdinaryFilesStillEnumerate);
    CPPUNIT_TEST(testDirectoryTypeAndRecursion);
    CPPUNIT_TEST(testChecksumHelperMatchesFixtures);
    CPPUNIT_TEST(testStatusStringsAreDistinct);
    CPPUNIT_TEST_SUITE_END();

public:
    void setUp();
    void tearDown();

    void testCompleteSetIsVerified();
    void testChecksumMismatchIsFlagged();
    void testDeletedSetIsRecoverable();
    void testDeletedSetWithBadChecksumIsUnconfirmed();
    void testMissingNameEntryDoesNotStealNextFile();
    void testMissingStreamDoesNotStealNextFile();
    void testOutOfOrderEntriesDoNotJoinSet();
    void testTruncatedAtEndOfDirectory();
    void testOrdinaryFilesStillEnumerate();
    void testDirectoryTypeAndRecursion();
    void testChecksumHelperMatchesFixtures();
    void testStatusStringsAreDistinct();
};

#endif /* EXFAT_DENTRY_SET_TEST_H_ */
