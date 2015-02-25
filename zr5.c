#include "zr5.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Note that data types are defined in "sha3/sph_types.h", included by each of these
#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

enum {KECCAK = -1, BLAKE, GROESTL, JH, SKEIN} ziftrAlgoIDs;

void zr5_hash(const char* input, char* output, uint32_t len)
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

    uint32_t				hash[5][16];	// buffers for 5 512bit (64 byte) hash outputs
    sph_blake512_context	ctx_blake;		// context for a blake hash
    sph_groestl512_context	ctx_groestl;	// context for a blake hash
    sph_jh512_context		ctx_jh;			// context for a blake hash
    sph_keccak512_context	ctx_keccak;		// context for a blake hash
    sph_skein512_context	ctx_skein;		// context for a blake hash
//    int						shiftbits;	// unused
    unsigned int			nOrder;			// order in which to apply the hashing algos
    unsigned int			i = 0; 			// loop counter

    // Represent uint512 values as arrays of bytes because we don't have a native uint512
    char * pStart;
    char * pPutResult;
    size_t nSize        = len;				// length of input buffer in bytes

    // Always start with a Keccak hash
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, nSize);
    // and put its output into the first hash output buffer
    sph_keccak512_close(&ctx_keccak, hash[0]);
    // Output from the keccak is the input to the next hash algorithm.

    // Calculate the order of the remaining hashes
    // by taking least significant 32 bits of the first hash,
    // treating that as an integer, which we divide modulo array size,
    // giving us an index into the array of hashing orders
	nOrder = getinnerint(&hash[0], 0, sizeof(hash[0]) ) % ARRAYLEN(arrOrder);
	// The output of each of the five hashes is 512bits = 64 bytes.
	// Therefore, the input to the last four hashes is also 64 bytes.
	nSize      = 64;

    // now apply the remaining hashes in the calculated order
    for (i = 0; i < 4; i++) {
        pStart     = (char *)(&hash[i]);
        pPutResult = (char *)(&hash[i+1]);

        // apply blake, groestl, jh, and skein in an order determined by the
        // result of the keccak hash
        switch (arrOrder[nOrder][i]) {
        case BLAKE:
            sph_blake512_init(&ctx_blake);
            sph_blake512 (&ctx_blake, pStart, nSize);
            sph_blake512_close(&ctx_blake, pPutResult);
            break;
        case GROESTL:
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512 (&ctx_groestl, pStart, nSize);
            sph_groestl512_close(&ctx_groestl, pPutResult);
            break;
        case JH:
            sph_jh512_init(&ctx_jh);
            sph_jh512 (&ctx_jh, pStart, nSize);
            sph_jh512_close(&ctx_jh, pPutResult);
            break;
        case SKEIN:
            sph_skein512_init(&ctx_skein);
            sph_skein512 (&ctx_skein, pStart, nSize);
            sph_skein512_close(&ctx_skein, pPutResult);
            break;
        default:
            break;
        }
    }

    // trim off all but the lowest 256 bits
    // TBD
    // copy the 64 bytes of the last hash into the output buffer
    for (i = 0; i < 64; i++) {
    	// use index notation so we can continue to look at the values
    	output[i] = pPutResult[i];
    }
    return;
}


// WARNING: This routine only works for little endian numbers
uint32_t getleastsig32( uint32_t* buffer, unsigned int nIndex)
{
	uint32_t	result;

	//return pn[nIndex % WIDTH];
	result = buffer[nIndex % sizeof(uint32_t)];

	return(result);
}
