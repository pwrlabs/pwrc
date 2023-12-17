#pragma once

#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    BIGNUM *r;
    BIGNUM *s;
} ecdsa_signature;

void init_ecdsa_signature(ecdsa_signature *sig, BIGNUM *r, BIGNUM *s) {
    sig->r = r;
    sig->s = s;
}

static EC_GROUP *curve = NULL;

void signature_initialize() {
    curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!curve) {
        // Handle the error, C doesn't support exceptions
        fprintf(stderr, "Failed to create curve group\n");
        exit(EXIT_FAILURE);
    }
}

unsigned char *sign_message(const unsigned char *message, size_t message_len, const BIGNUM *private_key, size_t *signature_len) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(key, private_key);

    unsigned char message_hash[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, message_hash);

    ECDSA_SIG *signature = ECDSA_do_sign(message_hash, SHA256_DIGEST_LENGTH, key);
    if (!signature) {
        fprintf(stderr, "Error signing message\n");
        EC_KEY_free(key);
        return NULL;
    }

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(signature, &r, &s);

    int r_len = BN_num_bytes(r);
    int s_len = BN_num_bytes(s);
    *signature_len = r_len + s_len;
    unsigned char *signature_bytes = malloc(*signature_len);
    BN_bn2bin(r, signature_bytes);
    BN_bn2bin(s, signature_bytes + r_len);

    ECDSA_SIG_free(signature);
    EC_KEY_free(key);
    return signature_bytes;
}

#endif