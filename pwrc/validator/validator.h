#pragma once

#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>
#include "cJSON.h"

typedef struct {
    char* address;
    char* ip;
    int bad_actor; // Using int for boolean representation
    long voting_power;
    long shares;
    int delegators_count;
    char* status;
    // ... Other fields ...
} validator;

validator* create_validator(const char* address, const char* ip, int bad_actor, long voting_power, long shares, int delegators_count, const char* status) {
    validator* v = malloc(sizeof(validator));
    if (v) {
        v->address = strdup(address);
        v->ip = strdup(ip);
        v->bad_actor = bad_actor;
        v->voting_power = voting_power;
        v->shares = shares;
        v->delegators_count = delegators_count;
        v->status = strdup(status);
        // ... Initialize other fields ...
    }
    return v;
}

// ... Getter and free_validator functions ...

// Function to perform HTTP GET request
char* http_get_request(const char* url) {
    CURL* curl = curl_easy_init();
    if (!curl) return NULL;

    char* response = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback); // Assuming write_callback is implemented
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        free(response);
        response = NULL;
    }

    curl_easy_cleanup(curl);
    return response; // Caller must free this memory
}

// Function to get delegators of a validator
cJSON* get_delegators(const validator* v) {
    if (!v || !v->address) return NULL;

    // Construct the URL for request
    char url[1024];
    snprintf(url, sizeof(url), "http://example.com/validator/delegatorsOfValidator/?validatorAddress=%s", v->address);

    char* response = http_get_request(url);
    if (!response) return NULL;

    cJSON* json_response = cJSON_Parse(response);
    free(response);

    if (!json_response) return NULL;

    cJSON* delegators = cJSON_GetObjectItemCaseSensitive(json_response, "delegators");
    if (!delegators) {
        cJSON_Delete(json_response);
        return NULL;
    }

    // Clone the delegators object to return
    cJSON* delegators_clone = cJSON_Duplicate(delegators, 1);
    cJSON_Delete(json_response);

    return delegators_clone; // Caller must free this with cJSON_Delete
}

#endif // VALIDATOR_H
