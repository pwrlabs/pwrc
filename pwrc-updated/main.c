#include <stdio.h>
#include "protocol/pwr.h"   
#include "utils/pwr_wallet.h" 
#include "utils/response.h"   
#include <curl/curl.h>
#include "utils/keccak256.h"

// Assuming you have these global variables and functions declared in PWR.h
extern void set_rpc_node_url(const char* url);

int main() {
    // Initialize libcurl (if it's used in any of the PWR functions)
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Set RPC node URL
    set_rpc_node_url("https://pwrrpc.pwrlabs.io/");
    rpc_node_url = get_rpc_node_url(); // Assuming this function is implemented

    // Create a PWRWallet instance with a specific private key
    const char *private_key = "48157030754737918552913355043337580418007638602253380155554472945119041505152";
    pwr_wallet* wallet = pwr_wallet_init_dec(private_key);
    if (wallet == NULL) {
        printf("Failed to create wallet.\n");
        return 1;
    }

    // Get wallet address (assuming getAddress is implemented to return a char*)
    char* address = pwr_wallet_get_address(wallet);
    if (address == NULL) {
        printf("Failed to get wallet address.\n");
        pwr_wallet_free(wallet);
        return 1;
    }

    printf("Wallet address: %s\n", address);

    // Assuming response struct and related functions are defined in Response.h
    response* resp = create_response(1, address, ""); // Assuming success is true and there is no error
    if (resp == NULL) {
        printf("Failed to create response.\n");
        pwr_wallet_free(wallet);
        free(address);
        return 1;
    }

    printf("Success: %d\n", is_success_(resp));
    printf("Txn Hash: %s\n", get_txn_hash(resp));    
    printf("Error: %s\n", get_error(resp));

    // Clean up
    pwr_wallet_free(wallet);
    free(address);
    free_response(resp);
    free(rpc_node_url);

    // Cleanup libcurl resources
    curl_global_cleanup();

    return 0;
}
