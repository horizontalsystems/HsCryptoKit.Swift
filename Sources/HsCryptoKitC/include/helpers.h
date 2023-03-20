//
//  Header.h
//
//
//  Created by Esenbek Kydyr uulu on 18/3/23.
//

#ifndef HELPERS_H
#define HELPERS_H

#include <stdint.h>

typedef struct {
    /* X = sum(i=0..4, n[i]*2^(i*52)) mod p
     * where p = 2^256 - 0x1000003D1
     */
    uint64_t n[5];
} secp256k1_fe;

void secp256k1_fe_clear(secp256k1_fe *a);
int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a);
void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a);
void secp256k1_fe_normalize_var(secp256k1_fe *r);

#endif /* HELPERS_H */
