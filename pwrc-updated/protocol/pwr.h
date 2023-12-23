#pragma once

#ifndef PWR_H
#define PWR_H

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
//#include "../utils/hash.h"
#include "../utils/response.h" 
#include "../block/block.h"


// Global variables
static CURL* curl = NULL;
static char* rpc_node_url = NULL;
static long fee_per_byte = 0;

void set_rpc_node_url(const char* url) {
    if (rpc_node_url != NULL) {
        free(rpc_node_url);
    }
    rpc_node_url = strdup(url);
}

char* to_hex_string(const unsigned char* input, size_t input_len) {
    char* output = malloc(input_len * 2 + 1);
    if (output) {
        for (size_t i = 0; i < input_len; ++i) {
            sprintf(output + i * 2, "%02x", input[i]);
        }
        output[input_len * 2] = '\0'; // Null-terminating the string
    }
    return output;
}

char* get_rpc_node_url() {
    return strdup(rpc_node_url);
}

void update_fee_per_byte(long fee) {
    fee_per_byte = fee;
}

// Helper function for writing the response data
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char** response = (char**)userp;
    char* ptr = realloc(*response, strlen(*response) + realsize + 1);
    
    if(ptr == NULL) return 0; // Out of memory

    *response = ptr;
    memcpy(&(ptr[strlen(*response)]), contents, realsize);
    ptr[strlen(*response) + realsize] = '\0';

    return realsize;
}

char* perform_http_get_request(const char* url) {
    if (curl == NULL) {
        curl = curl_easy_init();
        if (!curl) return NULL;
    }

    char* response = calloc(1, sizeof(char));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        free(response);
        return NULL;
    }

    return response;
}

char* perform_http_post_request(const char* url, const char* post_data) {
    if (curl == NULL) {
        curl = curl_easy_init();
        if (!curl) return NULL;
    }

    char* response = calloc(1, sizeof(char));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        free(response);
        return NULL;
    }

    return response;
}

int get_nonce_of_address(const char* address) {
    if (!rpc_node_url || !address) return -1;  // Return -1 or another appropriate error code

    char url[512];
    snprintf(url, sizeof(url), "%s/nonceOfUser/?userAddress=%s", rpc_node_url, address);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return -1;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return -1;

    cJSON* nonce_item = cJSON_GetObjectItemCaseSensitive(json_response, "nonce");
    int nonce = -1;  // Default error value
    if (cJSON_IsNumber(nonce_item)) {
        nonce = nonce_item->valueint;
    }

    cJSON_Delete(json_response);
    return nonce;
}

int get_balance_of_address(const char* address) {
    if (!rpc_node_url || !address) return -1;  // Return -1 or another appropriate error code

    char url[512];
    snprintf(url, sizeof(url), "%s/balanceOf/?userAddress=%s", rpc_node_url, address);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return -1;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return -1;

    cJSON* nonce_item = cJSON_GetObjectItemCaseSensitive(json_response, "balance");
    int nonce = -1;  // Default error value
    if (cJSON_IsNumber(nonce_item)) {
        nonce = nonce_item->valueint;
    }

    cJSON_Delete(json_response);
    return nonce;   
}

long get_blocks_count() {
    if (!rpc_node_url) return -1;  // Return -1 or an appropriate error code

    char url[512];
    snprintf(url, sizeof(url), "%s/blocksCount/", rpc_node_url);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return -1;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return -1;

    cJSON* blocks_count_item = cJSON_GetObjectItemCaseSensitive(json_response, "blocksCount");
    long blocks_count = -1;  // Default error value
    if (cJSON_IsNumber(blocks_count_item)) {
        blocks_count = blocks_count_item->valuedouble;
    }

    cJSON_Delete(json_response);
    return blocks_count;
}

long get_latest_block_number() {
    return get_blocks_count() - 1;
}

static block_t blk;
block_t* get_block_by_number(long blockNumber) {
    if (!rpc_node_url) return NULL;

    char url[512];
    snprintf(url, sizeof(url), "%s/block/?blockNumber=%ld", rpc_node_url, blockNumber);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return NULL;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return NULL;

    cJSON* block_item = cJSON_GetObjectItemCaseSensitive(json_response, "block");
    if (block_item != NULL && cJSON_IsObject(block_item)) {
        init_block(&blk, block_item); // Assuming this function is defined to parse a block from JSON
    }

    cJSON_Delete(json_response);
    return &blk;
}

int get_total_validators_count(const char* address) {
    if (!rpc_node_url || !address) return -1;  // Return -1 or another appropriate error code

    char url[512];
    snprintf(url, sizeof(url), "%s/totalValidatorsCount/%s", rpc_node_url, address);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return -1;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return -1;

    cJSON* nonce_item = cJSON_GetObjectItemCaseSensitive(json_response, "validatorsCount");
    int nonce = -1;  // Default error value
    if (cJSON_IsNumber(nonce_item)) {
        nonce = nonce_item->valueint;
    }

    cJSON_Delete(json_response);
    return nonce;   
}

int get_standby_validators_count(const char* address) {
    if (!rpc_node_url || !address) return -1;  // Return -1 or another appropriate error code

    char url[512];
    snprintf(url, sizeof(url), "%s/standbyValidatorsCount/%s", rpc_node_url, address);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return -1;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return -1;

    cJSON* nonce_item = cJSON_GetObjectItemCaseSensitive(json_response, "standbyValidatorsCount");
    int nonce = -1;  // Default error value
    if (cJSON_IsNumber(nonce_item)) {
        nonce = nonce_item->valueint;
    }

    cJSON_Delete(json_response);
    return nonce;   
}

int get_active_validators_count(const char* address) {
    if (!rpc_node_url || !address) return -1;  // Return -1 or another appropriate error code

    char url[512];
    snprintf(url, sizeof(url), "%s/activeValidatorsCount/%s", rpc_node_url, address);

    char* response_str = perform_http_get_request(url);
    if (!response_str) return -1;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return -1;

    cJSON* nonce_item = cJSON_GetObjectItemCaseSensitive(json_response, "activeValidatorsCount");
    int nonce = -1;  // Default error value
    if (cJSON_IsNumber(nonce_item)) {
        nonce = nonce_item->valueint;
    }

    cJSON_Delete(json_response);
    return nonce;   
}

cJSON* get_share_Value(const char** validators, size_t count, long blockNumber) {
    if (!rpc_node_url || !validators || count == 0) return NULL;

    // Construct the URL for the request
    char url[512];
    snprintf(url, sizeof(url), "%s/getShareValue/", rpc_node_url);

    // Create JSON payload
    cJSON* json_payload = cJSON_CreateObject();
    cJSON* json_validators = cJSON_AddArrayToObject(json_payload, "validators");
    for (size_t i = 0; i < count; ++i) {
        cJSON_AddItemToArray(json_validators, cJSON_CreateString(validators[i]));
    }
    cJSON_AddNumberToObject(json_payload, "blockNumber", blockNumber);

    char* payload_str = cJSON_PrintUnformatted(json_payload);
    cJSON_Delete(json_payload);

    if (!payload_str) return NULL;

    char* response_str = perform_http_post_request(url, payload_str);
    free(payload_str);

    if (!response_str) return NULL;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return NULL;

    // Clone the share values object to return
    cJSON* share_values = cJSON_GetObjectItemCaseSensitive(json_response, "shareValues");
    if (!share_values) {
        cJSON_Delete(json_response);
        return NULL;
    }

    cJSON* share_values_clone = cJSON_Duplicate(share_values, 1);
    cJSON_Delete(json_response);

    return share_values_clone; // Caller must free this with cJSON_Delete
}

response* broadcast_txn(const unsigned char* txn, size_t txn_size) {
    char* txn_hex = to_hex_string(txn, txn_size);
    if (!txn_hex) return NULL;

    char url[512];
    snprintf(url, sizeof(url), "%s/broadcast/", rpc_node_url);

    cJSON* json_payload = cJSON_CreateObject();
    cJSON_AddStringToObject(json_payload, "txn", txn_hex);
    char* json_str = cJSON_PrintUnformatted(json_payload);
    cJSON_Delete(json_payload);
    free(txn_hex);

    if (!json_str) return NULL;

    char* response_str = perform_http_post_request(url, json_str);
    free(json_str);

    if (!response_str) return NULL;

    cJSON* json_response = cJSON_Parse(response_str);
    free(response_str);

    if (!json_response) return NULL;

    response* resp = create_response(0, NULL, "message"); 
    cJSON_Delete(json_response);
    return resp;
}

#endif // PWR_H
