#pragma once

#ifndef PWR_WALLET_H
#define PWR_WALLET_H

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include "keccak256.h" // Include Keccak hash implementation header

typedef struct {
    BIGNUM* private_key;
} pwr_wallet;

// Function to initialize a new PWRWallet with a random private key
pwr_wallet* pwr_wallet_init() {
    pwr_wallet* wallet = malloc(sizeof(pwr_wallet));
    if (wallet) {
        wallet->private_key = BN_new();
        BN_rand(wallet->private_key, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    }
    return wallet;
}

// Function to initialize PWRWallet with a given hexadecimal private key
pwr_wallet* pwr_wallet_init_hex(const char* dex_private_key) {
    pwr_wallet* wallet = malloc(sizeof(pwr_wallet));
    if (wallet) {
        wallet->private_key = BN_new();
        BN_hex2bn(&wallet->private_key, dex_private_key);
    }
    return wallet;
}

// Function to initialize PWRWallet with a given binary private key
pwr_wallet* pwr_wallet_init_dec(const char* bin_private_key) {
    pwr_wallet* wallet = malloc(sizeof(pwr_wallet));
    if (wallet) {
         BN_dec2bn((&wallet->private_key), bin_private_key);
    }
    return wallet;
}

// Function to initialize PWRWallet with a BIGNUM private key
pwr_wallet* pwr_wallet_init_bignum(const BIGNUM* bn_private_key) {
    pwr_wallet* wallet = malloc(sizeof(pwr_wallet));
    if (wallet) {
        wallet->private_key = BN_dup(bn_private_key);
    }
    return wallet;
}

// Function to free PWRWallet
void pwr_wallet_free(pwr_wallet* wallet) {
    if (wallet) {
        BN_free(wallet->private_key);
        free(wallet);
    }
}

BIGNUM* public_key_from_private(const BIGNUM* privKey) {
    char *hexstr = BN_bn2hex(privKey);
    printf("Hexadecimal: privKey: %s\n", hexstr);
    EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* pubPoint = EC_POINT_new(curve);
    BN_CTX* ctx = BN_CTX_new();

    EC_POINT_mul(curve, pubPoint, privKey, NULL, NULL, ctx);

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(curve, pubPoint, x, y, ctx);

    size_t x_size = BN_num_bytes(x);
    size_t y_size = BN_num_bytes(y);
    size_t pub_key_size = x_size + y_size;
    unsigned char *pub_key_bytes = malloc(pub_key_size);
    BN_bn2bin(x, pub_key_bytes);
    BN_bn2bin(y, pub_key_bytes + x_size);

    // Convert serialized bytes to BIGNUM
    BIGNUM *pub_key_bn = BN_bin2bn(pub_key_bytes, pub_key_size, NULL);

    // Cleanup
    free(pub_key_bytes);
    EC_POINT_free(pubPoint);
    EC_GROUP_free(curve);
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(y);

    return pub_key_bn;
}

char* to_hex_string_(const unsigned char* bytes, size_t length) {
    char* hexString = malloc(length * 2 + 1);
    for (size_t i = 0; i < length; ++i) {
        sprintf(hexString + i * 2, "%02x", bytes[i]);
    }
    hexString[length * 2] = '\0';
    return hexString;
}

void keccak256_hash(const unsigned char* input, size_t input_size, unsigned char* output) {
    SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, input, input_size);
    keccak_final(&ctx, output);
}

char* public_key_to_address(const BIGNUM* publicKey) {
    char *hexstr = BN_bn2hex(publicKey);
    printf("Hexadecimal: publicKey: %s\n", hexstr);
    int publicKeySize = BN_num_bytes(publicKey);
    unsigned char* publicKeyBytes = malloc(publicKeySize);
    BN_bn2bin(publicKey, publicKeyBytes);

    // Perform Keccak-256 hashing on the public key
    unsigned char hashedPubKey[32]; // Keccak-256 hash size
    keccak256_hash(publicKeyBytes, publicKeySize, hashedPubKey);
    free(publicKeyBytes);

    // Take the last 20 bytes of the hashed public key
    char* address = to_hex_string_(hashedPubKey + 12, 20); // Ethereum addresses are 20 bytes
    return address;
}

char* pwr_wallet_get_address(pwr_wallet* wallet) {
    if (wallet) {
        BIGNUM* public_key = public_key_from_private(wallet->private_key);
        char* address = public_key_to_address(public_key);
        BN_free(public_key);
        return address;
    }
    return NULL;
}

#endif // PWR_WALLET_H
