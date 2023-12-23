#pragma once

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdlib.h>
#include <string.h>

typedef struct {
    int size;
    int position_in_block;
    long fee;
    char *type;
    char *from;
    char *to;
    char *nonce_or_validation_hash;
    char *hash;
    char* validator;
    long amount;
} transaction;

void init_transaction(transaction *txn, int size, int position_in_block, long fee,
                      const char *type, const char *from, const char *to,
                      const char *nonce_or_validation_hash, const char *hash, const char *validator, long amount) {
    txn->size = size;
    txn->position_in_block = position_in_block;
    txn->fee = fee;
    txn->type = strdup(type);
    txn->from = strdup(from);
    txn->to = strdup(to);
    txn->nonce_or_validation_hash = strdup(nonce_or_validation_hash);
    txn->hash = strdup(hash);
    txn->validator = strdup(validator);
    txn->amount = amount;
}

int get_transaction_size(const transaction *txn) {
    return txn->size;
}

int get_transaction_position_in_block(const transaction *txn) {
    return txn->position_in_block;
}

long get_transaction_fee(const transaction *txn) {
    return txn->fee;
}

const char *get_transaction_type(const transaction *txn) {
    return txn->type;
}

const char *get_transaction_from(const transaction *txn) {
    return txn->from;
}

const char *get_transaction_to(const transaction *txn) {
    return txn->to;
}

const char *get_transaction_nonce_or_validation_hash(const transaction *txn) {
    return txn->nonce_or_validation_hash;
}

const char *get_transaction_hash(const transaction *txn) {
    return txn->hash;
}

const char *get_transaction_validator(const transaction *txn) {
    return txn->validator;
}

long get_transaction_amount(const transaction *txn) {
    return txn->amount;
}

void free_transaction(transaction *txn) {
    free(txn->type);
    free(txn->from);
    free(txn->to);
    free(txn->nonce_or_validation_hash);
    free(txn->hash);
    free(txn->validator);
}
#endif // TRANSACTION_H
