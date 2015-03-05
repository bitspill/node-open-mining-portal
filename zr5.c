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

void zr5_512_hash(const char* input, char* output, uint32_t len)
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

    return;
}


void zr5_hash(const char* input, char* output, uint32_t len)
{
	char			input512[64];							// writeable copy of input
	char			output512[64];							// output of both zr5 hashes
	int*			versionPtr = (int *)input;				// pointer to version in data
	int				version;								// writeable copy of version
	unsigned int	nPoK;									// integer copy of PoK state
	static const unsigned int POK_BOOL_MASK = 0x00008000;
	static const unsigned int POK_DATA_MASK = 0xFFFF0000;
	unsigned int	i;										// generic loop counter

	// store the version
	versionPtr = (int *)input;
	version = *versionPtr;

	// copy the input buffer at input to a modifiable location at input512,
	memcpy((void *)input512, (void *)input, len);
	// then clear the version (second two bytes of the first four) in the input buffer
	// (standard convention before cryptocurrency hashing)
	for (i=2; i<4 ; i++) {
		input512[i] = 0;
	}

	// apply the first hash, yielding 512bits = 64 bytes
	zr5_512_hash(input, output512, len);

	// Pull the data from the result for the Proof of Knowledge
	// (this is the last four bytes of the result)
	ASSERT( (sizeof(output512) - 4) == 60);
	memcpy((void *)&nPoK, (void *)output512 + (sizeof(output512) - 4), 4);

	// update the version field in the input buffer
	// according to the Proof of Knowledge setting
	version &= (~POK_BOOL_MASK);
	version |= (POK_DATA_MASK & nPoK);
	// and now write it back out to the input buffer
	memcpy((void *)input512, (void *)&version, 4);

	// apply a second hash of the same type, 512 bits in and out
	zr5_512_hash(input512, output512, 64);

    // copy the right-most 256 bits (32 bytes) of the last hash into the output buffer
    // TBD: replace the loop with a memcpy()
    ASSERT( sizeof(output512)/2 == 32);
    memcpy((void *)output, (void *)output512 + sizeof(output512)/2, sizeof(output512)/2);

    return;
}


// WARNING: This routine only works for little endian numbers!
uint32_t getleastsig32( uint32_t* buffer, unsigned int nIndex)
{
	uint32_t	result;

	//return pn[nIndex % WIDTH];
	result = buffer[nIndex % sizeof(uint32_t)];

	return(result);
}

#endif


#ifdef TEST_ZR5
// This code is C++ code, whether it looks like it or not
// g++ -DTEST_ZR5=1 *.c sha3/*.c -o testzr5
int main(int argc, char* argv[])
{
	int			passed = 0;
	int			failed = 0;
	char		zr5_out_512[64];
	char		test0[] = {	0x01000000, 0x4e42b759, 0xbd656859, 0x9cff714b, 0x679dbf94,
							0x6543c9ba, 0x8444f7b8, 0xb964bf21, 0x71070000, 0xc6bb8526,
							0xc7e59d3b, 0xc92afd77, 0xb11e544a, 0xf69ae0d4, 0xda4f98bc,
							0x6e981f3d, 0xbb20f185, 0xa918e654, 0xffff0b1e, 0x00000000 };
	// three byte test
	char		test1[] = {	0x001122 };
	char	xpec1_512[] = {	0xf52f444f, 0x7ee6a50b, 0x197cc9f0, 0x3ed02dbe, 0xec3de910,
							0xd184b1d2, 0x03c7f1e0, 0x454ed1b3, 0x280aab39, 0xdc67a6ff,
							0xdbdb428c, 0x48cea4ae, 0x5ea56015, 0x4c8ad016, 0xddf38d2e,
							0x7c49fc2e };
	char		xpec1[] = {	0x280aab39, 0xdc67a6ff, 0xdbdb428c, 0x48cea4ae, 0x5a560154,
							0xc8ad016d, 0xdf38d2e7, 0xc49fc2e };

	// 65 byte test
	char		test2[] = {	0x04fc9702, 0x847840aa, 0xf195de84, 0x42ebeced, 0xf5b095cd,
							0xbb9bc716, 0xbda91109, 0x71b28a49, 0xe0ead856, 0x4ff0db22,
							0x209e0374, 0x782c093b, 0xb899692d, 0x524e9d6a, 0x6956e7c5,
							0xecbcd682, 0x84 };
	char	xpec2_512[] = {	0xa79ceb61, 0x08a9e3f0, 0xcf4ad6d0, 0x50461976, 0xaaaeb1a4,
							0xa85bcbb3, 0x842646f9, 0x9df7f6c3, 0x85ffc1bf, 0x480841e3,
							0x6570d69f, 0xd85fffe5, 0xd921666c, 0xad288b70, 0xc94a40e2,
							0xd4a2c928 };
	char		xpec2[] = {	0x85ffc1bf, 0x480841e3, 0x6570d69f, 0xd85fffe5, 0xd921666c,
							0xad288b70, 0xc94a40e2, 0xd4a2c928 };

	// 80 byte test
	char		test3[] = {	0x01806486, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
							0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x2ab03251,
							0x87d4f28b, 0x6e22f086, 0x4845ddd5, 0x0ac4e6aa, 0x22a1709f,
							0xfb4275d9, 0x25f26636, 0x300eed54, 0xffff0f1e, 0x2a9e2300 };
	char	xpec3_512[] = {	0xee0c3d3b, 0xe3dc49ed, 0x47a60bda, 0x98761ec6, 0x012b8c3f,
							0x54c586d1, 0x009fe596, 0xefc54c35, 0x00000358, 0x88fea2f9,
							0x6e3ef996, 0xbeda4fa4, 0xc4c4d03b, 0x371184d1, 0xf575f9d1,
							0x44b7a164 };
	char		xpec3[] = {	0x00000358, 0x88fea2f9, 0x6e3ef996, 0xbeda4fa4, 0xc4c4d03b,
							0x371184d1, 0xf575f9d1, 0x44b7a164 };
	char	xr5_out[64];

	zr5_hash_512(test1, zr5_out_512, sizeof(test1) );
	if (strncmp(zr5_out_512, xpec1, 64) == 0) {
		passed += 1;
		zr5_hash(test1, zr5_out_512, sizeof(test1) );
		if (strncmp(zr5_out_512, xpec1, 32) == 0) {
			passed += 1;
		}
		else {
			failed += 1;
		}
	}
	else {
		failed += 2;
	}
	zr5_hash(test2, zr5_out_512, sizeof(test2) );
	zr5_hash(test3, zr5_out_512, sizeof(test3) );

	return 0;
}

