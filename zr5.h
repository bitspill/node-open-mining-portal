#ifndef ZR5_H
#define ZR5_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
//#include "uint256.h"

#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))
#define WIDTH	(BITS/32)
static const unsigned int VERSION_MASK  = 0x00007FFF;
static const unsigned int POK_BOOL_MASK = 0x00008000;
static const unsigned int POK_DATA_MASK = 0xFFFF0000;


void zr5_hash(const char* input, char* output, uint32_t len);
void zr5_512_hash(const char* input, char* output, uint32_t len);
uint32_t getleastsig32( uint32_t* buffer, unsigned int nIndex);

//uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
//{
//    CHashWriter ss(nType, nVersion);
//    ss << obj;
//    return ss.GetHash();
//}

#ifdef __cplusplus
}
#endif

#endif
