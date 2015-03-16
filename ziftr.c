/*
 * Copyright 2014 mkimid
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sph_keccak.h"

//--grs include ---
#include "jack/grso.c"
#include "jack/grso-asm.c"
//--jh include ---
#include "jack/jh_sse2_opt64.h"
//--skein include ---
#include "jack/skein.c"
//--blake include ---
#include "jack/blake.c"
/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

#define ZR_BLAKE 0
#define ZR_GROESTL 1
#define ZR_JH 2
#define ZR_SKEIN 3
#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

//static void ziftrhash_debug(void *state, const void *input) {
   
//}


static void ziftrhash(void *state, const void *input) {
    
sph_keccak512_context    ctx_keccak;
   
DATA_ALIGN16(unsigned char hashbuf[128]);
DATA_ALIGN16(unsigned char hash[128]);
DATA_ALIGN16(size_t hashptr);
DATA_ALIGN16(sph_u64 hashctA);
DATA_ALIGN16(sph_u64 hashctB);
memset(hash, 0, 128);
grsoState sts_grs;
static const int arrOrder[][4] =
{
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

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, input, 80);
    sph_keccak512_close(&ctx_keccak, hash);
  
    //unsigned int round;
	unsigned int nOrder = *(unsigned int *)(&hash) % 24;
	unsigned int i = 0;
	for (i = 0; i < 4; i++)
{
switch (arrOrder[nOrder][i])
{
case 0:
			{DECL_BLK;
			BLK_I;
			BLK_U;
			BLK_C;}
		break;
case 1:
			{GRS_I;
			GRS_U;
			GRS_C; }
		break;
case 2:
			{DECL_JH;
			JH_H;} 
		break;
case 3:
			{DECL_SKN;
            SKN_I;
            SKN_U;
            SKN_C; }
		break;
default:
break;
}
}
	asm volatile ("emms");
	memcpy(state, hash, 32);
}

int scanhash_ziftr(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done) {
	uint32_t hash[16] __attribute__((aligned(64)));
uint32_t tmpdata[20] __attribute__((aligned(64)));
const uint32_t version = pdata[0] & (~POK_DATA_MASK);
const uint32_t first_nonce = pdata[19];
uint32_t nonce = first_nonce;
memcpy(tmpdata, pdata, 80);
do {
#define Htarg ptarget[7]
tmpdata[0] = version;
tmpdata[19] = nonce;
ziftrhash(hash, tmpdata);
tmpdata[0] = version | (hash[0] & POK_DATA_MASK);
ziftrhash(hash, tmpdata);
if (hash[7] <= Htarg && fulltest(hash, ptarget))
{
pdata[0] = tmpdata[0];
pdata[19] = nonce;
*hashes_done = pdata[19] - first_nonce + 1;
if (opt_debug)
applog(LOG_INFO, "found nonce %x", nonce);
return 1;
}
nonce++;
} while (nonce < max_nonce && !work_restart[thr_id].restart);
pdata[19] = nonce;
*hashes_done = pdata[19] - first_nonce + 1;
return 0;
}