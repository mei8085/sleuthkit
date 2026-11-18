/*
 * vs_partition_boundary_test.h
 *
 * Copyright (c) 2026
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Unit tests for partition boundary analysis: unallocated volume space
 * calculation (tsk_vs_part_unused via tsk_vs_open) and volume interval
 * queries (tsk_vs_part_get / tsk_vs_part_walk and the TskVsInfo C++
 * wrappers) over locally synthesized DOS/MBR and GPT images.
 */

#ifndef VS_PARTITION_BOUNDARY_TEST_H
#define VS_PARTITION_BOUNDARY_TEST_H

#include <cppunit/extensions/HelperMacros.h>

class VsPartitionBoundaryTest : public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(VsPartitionBoundaryTest);

    /* Valid GPT/MBR layouts, including minimum and maximum representable
     * entry ranges, must keep their original interval results. */
    CPPUNIT_TEST(testValidGptLayoutIntervals);
    CPPUNIT_TEST(testValidDosLayoutIntervals);

    /* Malformed tables must fail with structured, locatable errors before
     * any truncated free region or out-of-bounds read can be produced. */
    CPPUNIT_TEST(testMalformedOverlapRejected);
    CPPUNIT_TEST(testMalformedBeyondEndRejected);
    CPPUNIT_TEST(testMalformedZeroLengthRejected);
    CPPUNIT_TEST(testMalformedMismatchedStartRejected);

    /* A failure on one stream must not pollute a subsequent valid parse of
     * the same input stream, and both entry points must agree. */
    CPPUNIT_TEST(testFailureDoesNotPolluteReuse);
    CPPUNIT_TEST(testEntryPointsConsistent);

    CPPUNIT_TEST_SUITE_END();

  public:
    void setUp();
    void tearDown();

    void testValidGptLayoutIntervals();
    void testValidDosLayoutIntervals();
    void testMalformedOverlapRejected();
    void testMalformedBeyondEndRejected();
    void testMalformedZeroLengthRejected();
    void testMalformedMismatchedStartRejected();
    void testFailureDoesNotPolluteReuse();
    void testEntryPointsConsistent();
};

#endif
