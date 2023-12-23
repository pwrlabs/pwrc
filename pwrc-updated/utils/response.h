#pragma once

#ifndef RESPONSE_H
#define RESPONSE_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Response struct
typedef struct {
    int success;   // Using int instead of bool for C compatibility
    char* txn_hash;
    char* error;
} response;

// Function to create a new response
response* create_response(int success, const char* txn_hash, const char* error) {
    response* resp = malloc(sizeof(response));
    if (resp) {
        resp->success = success;
        resp->txn_hash = txn_hash ? strdup(txn_hash) : NULL;
        resp->error = error ? strdup(error) : NULL;
    }
    return resp;
}

// Function to free the response
void free_response(response* resp) {
    if (resp) {
        free(resp->txn_hash);
        free(resp->error);
        free(resp);
    }
}

// Function to check if the operation was successful
int is_success_(const response* resp) {
    return resp ? resp->success : 0;
}

// Function to get the transaction hash
const char* get_txn_hash(const response* resp) {
    return resp ? resp->txn_hash : "";
}

// Function to get the error message
const char* get_error(const response* resp) {
    return resp ? resp->error : "";
}

#endif // RESPONSE_H