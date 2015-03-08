#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "zr5.h"
//#include "uint256.h"
// Note that data types are defined in "sha3/sph_types.h", included by each of these
#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {KECCAK = -1, BLAKE, GROESTL, JH, SKEIN} ziftrAlgoIDs;

static inline uint32_t Reverse32(uint32_t n)
{
	#if BYTE_ORDER == LITTLE_ENDIAN
		return n << 24 | (n & 0x0000ff00) << 8 | (n & 0x00ff0000) >> 8 | n >> 24;
	#else
		return n;
	#endif
}


void zr5_hash_512( uint8_t* input, uint8_t* output, uint32_t len )
{
    //static const uint256 INT_MASK("0xFFFFFFFF");
    //static unsigned char pblank[1];
    //pblank[0] = 0;

    // Pre-computed table of permutations
    static const int arrOrder[][4] = {
        {0, 1, 2, 3},
        {0, 1, 3, 2},
        {0, 2, 1, 3},
        {0, 2, 3, 1},
        {0, 3, 1, 2},
        {0, 3, 2, 1},
        {1, 0, 2, 3},
        {1, 0, 3, 2},
        {1, 2, 0, 3},
        {1, 2, 3, 0},
        {1, 3, 0, 2},
        {1, 3, 2, 0},
        {2, 0, 1, 3},
        {2, 0, 3, 1},
        {2, 1, 0, 3},
        {2, 1, 3, 0},
        {2, 3, 0, 1},
        {2, 3, 1, 0},
        {3, 0, 1, 2},
        {3, 0, 2, 1},
        {3, 1, 0, 2},
        {3, 1, 2, 0},
        {3, 2, 0, 1},
        {3, 2, 1, 0}
    };

    uint8_t					hash[5][64];	// buffers for 5 512bit (64 byte) hash outputs
    sph_blake512_context	ctx_blake;		// context for a blake hash
    sph_groestl512_context	ctx_groestl;	// context for a blake hash
    sph_jh512_context		ctx_jh;			// context for a blake hash
    sph_keccak512_context	ctx_keccak;		// context for a blake hash
    sph_skein512_context	ctx_skein;		// context for a blake hash
//    int						shiftbits;	// unused
    unsigned int			nOrder;			// order in which to apply the hashing algos
    unsigned int			i = 0; 			// loop counter
    unsigned int			j = 0; 			// loop counter

    // Represent uint512 values as arrays of bytes because we don't have a native uint512
    uint8_t *				pStart;
    uint8_t *				pPutResult;
    size_t					nSize     = len;	// length of input buffer in bytes

	printf("%12s", "zr5-512in: ");
	for(j=0; j< len; j++) { printf("%02x", *(input + j) ); }
	printf("\n");

    // initialize the buffers for hash results
    for(i=0; i<5; i++) { for(j=0; j<64; j++) { hash[i][j] = 0; } }

    // initialize the four types of hashes outside the loop
    sph_keccak512_init(&ctx_keccak);
	sph_blake512_init(&ctx_blake);
	sph_groestl512_init(&ctx_groestl);
	sph_jh512_init(&ctx_jh);
	sph_skein512_init(&ctx_skein);

    // Always start with a Keccak hash
    sph_keccak512 (&ctx_keccak, input, len);
    // and put its output into the first hash output buffer
    sph_keccak512_close(&ctx_keccak, &(hash[0]));
    // Output from the keccak is the input to the next hash algorithm.
	printf("keccak[%d]: \n", 0);
	for(j=0; j< sizeof(hash[0]); j++) { printf("%02x", hash[0][j]); }
	printf("\n");

    // Calculate the order of the remaining hashes
    // by taking least significant 32 bits of the first hash,
    // treating that as an integer, which we divide modulo array size,
    // giving us an index into the array of hashing orders
	//nOrder = getinnerint(&hash[0], 0, sizeof(hash[0]) ) % ARRAYLEN(arrOrder);
	uint32_t gls32 = getleastsig32((uint8_t *)&hash[0], 0);
	nOrder = gls32 % ARRAYLEN(arrOrder);
	printf("\nGetleastsig32 = %u\n", gls32 );
	printf("%12s", "in hex: 0x");
	for(j=0; j< sizeof(uint32_t); j++) { printf("%02x", *( (uint8_t *)(&gls32) + j) ); }
	printf("\n");
	printf("nOrder = %d\n", nOrder);
	// The output of each of the five hashes is 512bits = 64 bytes.
	// Therefore, the input to the last four hashes is also 64 bytes.
	nSize      = 64;

    // now apply the remaining hashes in the calculated order
    // start loop counter at 0 so we start with keccak results
    for (i = 0; i < 4; i++) {
        pStart     = (uint8_t *)(&hash[i]);
        pPutResult = (uint8_t *)(&hash[i+1]);
        // have the result of the last hash go straight into the output buffer
        // in order to use one less buffer and avoid having to copy the last result
        if (i == 3)
        	pPutResult = output;

        // apply blake, groestl, jh, and skein in an order determined by the
        // result of the keccak hash
        switch (arrOrder[nOrder][i]) {
        case BLAKE:
            sph_blake512(&ctx_blake, pStart, nSize);
            sph_blake512_close(&ctx_blake, pPutResult);
			printf("blake[%d]:\n", i+1);
			for(j=0; j< sizeof(hash[i+1]); j++) { printf("%02x", hash[i+1][j]); }
			printf("\n");
            break;
        case GROESTL:
            sph_groestl512(&ctx_groestl, pStart, nSize);
            sph_groestl512_close(&ctx_groestl, pPutResult);
			printf("groestl[%d]:\n", i+1);
			for(j=0; j< sizeof(hash[i+1]); j++) { printf("%02x", hash[i+1][j]); }
			printf("\n");
            break;
        case JH:
            sph_jh512(&ctx_jh, pStart, nSize);
            sph_jh512_close(&ctx_jh, pPutResult);
			printf("jh_out[%d]:\n", i+1);
			for(j=0; j< sizeof(hash[i+1]); j++) { printf("%02x", hash[i+1][j]); }
			printf("\n");
            break;
        case SKEIN:
            sph_skein512(&ctx_skein, pStart, nSize);
            sph_skein512_close(&ctx_skein, pPutResult);
			printf("skein[%d]:\n", i+1);
			for(j=0; j< sizeof(hash[i+1]); j++) { printf("%02x", hash[i+1][j]); }
			printf("\n");
            break;
        default:
            break;
        }
    }

    return;
}


void zr5_hash( uint8_t* input, uint8_t* output, uint32_t len)
{
	uint8_t			input512[64];							// writeable copy of input
	uint8_t			output512[64];							// output of both zr5 hashes
	uint32_t		version;								// writeable copy of version
	uint32_t		nPoK = 0;									// integer copy of PoK state
	static const unsigned int POK_BOOL_MASK = 0x00008000;
	static const unsigned int POK_DATA_MASK = 0xFFFF0000;
	unsigned int	i;										// generic loop counter

	// store the version bytes
	memcpy((uint8_t *)&version, (uint8_t *)input, 4);

	printf("%12s", "input: ");
	for(i=0; i< len; i++) { printf("%02x", input[i]); }
	printf("\n");
	// copy the input buffer at input to a modifiable location at input512,
	memcpy((uint8_t *)input512, (uint8_t *)input, len);
	// then clear the version (second two bytes of the first four) in the input buffer
	// (standard convention before cryptocurrency hashing)
//	for (i=2; i<4 ; i++) {
//		input512[i] = 0;
//	}
//	printf("%12s", "inZeroed: ");
	for(i=0; i< len; i++) { printf("%02x", input512[i]); }
	printf("\n");

	// apply the first hash, yielding 512bits = 64 bytes
	zr5_hash_512(input512, output512, len);

	// Now begins Proof of Knowledge
	//
	// Pull the data from the result for the Proof of Knowledge
	// (this is the 3rd and 4th of the first four bytes of the result)
	memcpy(&nPoK, (uint8_t *)output512, 4);	// yields big or little endian uint
	// keep only the two least significant bytes
	#if BYTE_ORDER == LITTLE_ENDIAN
		nPoK &= 0xFFFF0000;		// bytes 3&4 of big endian are 1&2 of little endian
	#else
		nPoK &= 0x0000FFFF;		// bytes 3&4 of big endian are 1&2 of little endian
	#endif
//	nPoK = Reverse32(nPoK);		// reversal for little endian only
	printf("\n\nPok Value: %u\n", nPoK);

	// update the version variable with the masks and PoK value
	// according to the Proof of Knowledge setting
	printf("version field: %u\n", version);
	version &= (~POK_BOOL_MASK);
	version |= (POK_DATA_MASK & nPoK);
	printf("new version field: %u\n", version);
	printf("input before PoK modification:\n");
	for(i=0; i< len; i++) { printf("%02x", input512[i]); }
	printf("\n");
	// and now write it back out to the input buffer
	memcpy((uint8_t *)input512, (uint8_t *)&version, 4);
	printf("Input modified with PoK: %u\n", version);
	for(i=0; i< len; i++) { printf("%02x", input512[i]); }
	printf("\n");

	// apply a second hash of the same type, 512 bits in and out,
	// to the input modified with PoK
	zr5_hash_512(input512, output512, len);

    // copy the right-most 256 bits (32 bytes) of the last hash into the output buffer
    // TBD: replace the loop with a memcpy()
    //if( sizeof(output512)/2 == 32)
    //	printf("rightmost half of 512 bits are where we expect them.\n");
    memcpy((uint8_t *)output, (uint8_t *)output512 + sizeof(output512)/2, sizeof(output512)/2);

    return;
}


// WARNING: This routine only works for little endian numbers!
uint32_t getleastsig32( uint8_t* buffer, unsigned int nIndex)
{
	uint32_t *	ptr = NULL;
	uint32_t	result;
	unsigned	uint32_offset;

	ptr = (uint32_t *)buffer;
	uint32_offset = nIndex % sizeof(uint32_t);
	printf("uint32_offset = %d\n", uint32_offset);
	result = ptr[nIndex % sizeof(uint32_t)];

	return(result);
}

#ifdef __cplusplus
}
#endif
