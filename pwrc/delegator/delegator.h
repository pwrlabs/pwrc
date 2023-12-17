#pragma once

#ifndef DELEGATOR_H
#define DELEGATOR_H

#include <stdlib.h>
#include <string.h>

// Delegator structure
typedef struct {
    char* address;
    char* validator_address;
    long shares;
    long delegated_pwr;
} delegator;

// Function to create a new Delegator
delegator* create_delegator(const char* address, const char* validator_address, long shares, long delegated_pwr) {
    delegator* d = malloc(sizeof(delegator));
    if (d != NULL) {
        d->address = strdup(address);
        d->validator_address = strdup(validator_address);
        d->shares = shares;
        d->delegated_pwr = delegated_pwr;
    }
    return d;
}

// Getters
const char* get_address(const delegator* d) {
    return d->address;
}

const char* get_validator_address(const delegator* d) {
    return d->validator_address;
}

long get_shares(const delegator* d) {
    return d->shares;
}

long get_delegated_pwr(const delegator* d) {
    return d->delegated_pwr;
}

// Function to free the Delegator
void free_delegator(delegator* d) {
    if (d != NULL) {
        free(d->address);
        free(d->validator_address);
        free(d);
    }
}

#endif // DELEGATOR_H
