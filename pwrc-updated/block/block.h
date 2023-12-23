#pragma once

#ifndef BLOCK_H
#define BLOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../transaction/transaction.h"
#include <cjson/cJSON.h>

typedef struct {
    int transaction_count;
    int size;
    long number;
    long reward;
    long timestamp;
    char* hash;
    char* submitter;
    int success;
    transaction* transactions;
} block_t;

void init_block(block_t *block, const cJSON* root) {

    if (root != NULL) {
        cJSON* txns_array = cJSON_GetObjectItem(root, "transactions");

        // Extract block information
        block->transaction_count = cJSON_GetObjectItem(root, "transactionCount")->valueint;
        block->size = cJSON_GetObjectItem(root, "blockSize")->valueint;
        block->number = cJSON_GetObjectItem(root, "blockNumber")->valuedouble;
        block->reward = cJSON_GetObjectItem(root, "blockReward")->valuedouble;
        block->timestamp = cJSON_GetObjectItem(root, "timestamp")->valuedouble;
        block->hash = strdup(cJSON_GetObjectItem(root, "blockHash")->valuestring);
        block->submitter = strdup(cJSON_GetObjectItem(root, "blockSubmitter")->valuestring);
        block->success = cJSON_GetObjectItem(root, "success")->type == cJSON_True;

        // Allocate memory for transactions
        block->transactions = (transaction*)malloc(sizeof(transaction) * block->transaction_count);

        // Extract transactions information
        int i = 0;
        cJSON* txn_object = NULL;
        cJSON_ArrayForEach(txn_object, txns_array) {
            init_transaction(&block->transactions[i], 
                                        cJSON_GetObjectItem(txn_object, "size")->valueint,
                                        cJSON_GetObjectItem(txn_object, "positionInTheBlock")->valueint,
                                        cJSON_GetObjectItem(txn_object, "fee")->valuedouble,
                                        cJSON_GetObjectItem(txn_object, "type")->valuestring,
                                        cJSON_GetObjectItem(txn_object, "from")->valuestring,
                                        cJSON_GetObjectItem(txn_object, "to")->valuestring,
                                        cJSON_GetObjectItem(txn_object, "nonceOrValidationHash")->valuestring,
                                        cJSON_GetObjectItem(txn_object, "hash")->valuestring,
                                        "UNKNOWN",
                                        -1);
            // Additional fields for specific transaction types
            if (strcmp(block->transactions[i].type, "Transfer") == 0) {
                block->transactions[i].amount = cJSON_GetObjectItem(txn_object, "value")->valuedouble;
            } else if (strcmp(block->transactions[i].type, "VM Data") == 0) {
                block->transactions[i].amount = cJSON_GetObjectItem(txn_object, "vmId")->valuedouble;
                free(block->transactions[i].hash);
                block->transactions[i].validator = strdup(cJSON_GetObjectItem(txn_object, "data")->valuestring);
            } else if (strcmp(block->transactions[i].type, "Delegate") == 0) {
                block->transactions[i].amount = cJSON_GetObjectItem(txn_object, "value")->valuedouble;
            } else if (strcmp(block->transactions[i].type, "Withdraw") == 0) {
                block->transactions[i].amount = cJSON_GetObjectItem(txn_object, "shares")->valuedouble;
            }// else - Validator Join or Unknown
            i ++;
        }
    } else {
        // Handle JSON parsing error
        fprintf(stderr, "Error parsing JSON.\n");
        exit(EXIT_FAILURE);
    }
}

// Getters and setters
int get_transaction_count(const block_t* block) {
    return block->transaction_count;
}

int get_size(const block_t* block) {
    return block->size;
}

long get_number(const block_t* block) {
    return block->number;
}

long get_reward(const block_t* block) {
    return block->reward;
}

long get_timestamp(const block_t* block) {
    return block->timestamp;
}

char* get_hash(const block_t* block) {
    return block->hash;
}

char* get_submitter(const block_t* block) {
    return block->submitter;
}

int is_success(const block_t* block) {
    return block->success;
}

transaction* get_transactions(const block_t* block) {
    return block->transactions;
}

void free_block(block_t* block) {
    if (block != NULL) {
        free(block->hash);
        free(block->submitter);

        for (int i = 0; i < block->transaction_count; i++) {
            free_transaction(&(block->transactions[i])); // assuming free_transaction is defined in transaction.h
        }

        free(block->transactions);
    }
}

#endif // BLOCK_H
