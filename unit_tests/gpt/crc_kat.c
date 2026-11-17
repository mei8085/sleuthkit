/* Known-answer test for tsk_crc32_uefi against UEFI/zlib CRC32 vectors. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "tsk/base/crc.h"
struct { const char *in; uint32_t want; } vec[] = {
    {"", 0x00000000},
    {"123456789", 0xCBF43926},   /* standard CRC-32 check vector */
    {"a", 0xE8B7BE43},
    {"The quick brown fox jumps over the lazy dog", 0x414FA339},
};
int main(void){
    int fails=0;
    for(size_t i=0;i<sizeof(vec)/sizeof(vec[0]);i++){
        size_t n=strlen(vec[i].in);
        uint32_t got=tsk_crc32_uefi(0,(const unsigned char*)vec[i].in,n);
        printf("%-45s got=%08x want=%08x %s\n", vec[i].in, got, vec[i].want,
            got==vec[i].want?"OK":"FAIL");
        if(got!=vec[i].want) fails++;
    }
    /* streaming/chunked equivalence */
    const char *m="chunked-update-check";
    uint32_t whole=tsk_crc32_uefi(0,(const unsigned char*)m,strlen(m));
    uint32_t c=0;
    c=tsk_crc32_uefi(c,(const unsigned char*)m,7);
    c=tsk_crc32_uefi(c,(const unsigned char*)m+7,strlen(m)-7);
    printf("chunked: whole=%08x streamed=%08x %s\n", whole,c,whole==c?"OK":"FAIL");
    if(whole!=c) fails++;
    printf(fails?"KAT FAILED\n":"KAT ALL PASSED\n");
    return fails?1:0;
}
