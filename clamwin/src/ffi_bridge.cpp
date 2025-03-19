/**
 * @file ffi_bridge.cpp
 * @brief FFI bridge between Rust and ClamWin C++ components
 * @copyright Amaru Contributors
 * @license GPL-2.0
 */

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <cstring>

#include "../include/amaru_clamwin.h"

// Export C-compatible interface for Rust FFI

extern "C" {

/**
 * Simplified result structure for FFI
 */
typedef struct {
    int32_t result_code;
    uint64_t scan_time_ms;
    uint8_t is_infected;
    const char* virus_name;
} amaru_ffi_result_t;

/**
 * Initialize ClamAV engine
 */
int32_t amaru_ffi_init(const char* db_path) {
    return amaru_cw_init(db_path);
}

/**
 * Cleanup ClamAV engine
 */
void amaru_ffi_cleanup() {
    amaru_cw_cleanup();
}

/**
 * Scan a file
 */
amaru_ffi_result_t amaru_ffi_scan_file(const char* path) {
    amaru_ffi_result_t ffi_result = {0};
    
    // Get default options
    amaru_cw_scan_options_t options = amaru_cw_default_options();
    
    // Initialize result structure
    amaru_cw_scan_result_t scan_result = {0};
    
    // Perform scan
    int32_t result = amaru_cw_scan_file(path, &options, &scan_result);
    
    // Copy results
    ffi_result.result_code = result;
    ffi_result.scan_time_ms = scan_result.scan_time_ms;
    ffi_result.is_infected = scan_result.is_infected ? 1 : 0;
    
    // Allocate memory for virus name (caller must free)
    if (scan_result.virus_name != nullptr && scan_result.virus_name[0] != '\0') {
        size_t len = strlen(scan_result.virus_name) + 1;
        char* virus_name = (char*)malloc(len);
        if (virus_name != nullptr) {
            memcpy(virus_name, scan_result.virus_name, len);
            ffi_result.virus_name = virus_name;
        } else {
            ffi_result.virus_name = nullptr;
        }
    } else {
        ffi_result.virus_name = nullptr;
    }
    
    return ffi_result;
}

/**
 * Free memory allocated for virus name in FFI result
 */
void amaru_ffi_free_result(amaru_ffi_result_t* result) {
    if (result != nullptr && result->virus_name != nullptr) {
        free((void*)result->virus_name);
        result->virus_name = nullptr;
    }
}

/**
 * Scan memory buffer
 */
amaru_ffi_result_t amaru_ffi_scan_memory(const uint8_t* buffer, size_t length) {
    amaru_ffi_result_t ffi_result = {0};
    
    // Get default options
    amaru_cw_scan_options_t options = amaru_cw_default_options();
    
    // Initialize result structure
    amaru_cw_scan_result_t scan_result = {0};
    
    // Perform scan
    int32_t result = amaru_cw_scan_memory(buffer, length, &options, &scan_result);
    
    // Copy results
    ffi_result.result_code = result;
    ffi_result.scan_time_ms = scan_result.scan_time_ms;
    ffi_result.is_infected = scan_result.is_infected ? 1 : 0;
    
    // Allocate memory for virus name (caller must free)
    if (scan_result.virus_name != nullptr && scan_result.virus_name[0] != '\0') {
        size_t len = strlen(scan_result.virus_name) + 1;
        char* virus_name = (char*)malloc(len);
        if (virus_name != nullptr) {
            memcpy(virus_name, scan_result.virus_name, len);
            ffi_result.virus_name = virus_name;
        } else {
            ffi_result.virus_name = nullptr;
        }
    } else {
        ffi_result.virus_name = nullptr;
    }
    
    return ffi_result;
}

/**
 * Get database version
 */
const char* amaru_ffi_get_db_version() {
    return amaru_cw_get_db_version();
}

/**
 * Get last error message
 */
const char* amaru_ffi_get_last_error() {
    return amaru_cw_get_last_error();
}

/**
 * A custom log callback function type
 */
typedef void (*amaru_ffi_log_callback_t)(const char* message);

/**
 * Global log callback instance
 */
static amaru_ffi_log_callback_t g_ffi_log_callback = nullptr;

/**
 * Internal log message handler that forwards to Rust
 */
static void internal_log_callback(const char* message) {
    if (g_ffi_log_callback != nullptr) {
        g_ffi_log_callback(message);
    }
}

/**
 * Set log callback
 */
void amaru_ffi_set_log_callback(amaru_ffi_log_callback_t callback) {
    g_ffi_log_callback = callback;
    amaru_cw_set_log_callback(internal_log_callback);
}

} // extern "C" 