/**
 * @file clamav_scanner.cpp
 * @brief Implementation of ClamAV scanning functionality
 * @copyright Amaru Contributors
 * @license GPL-2.0
 */

#include <clamav.h>
#include <string>
#include <chrono>
#include <memory>
#include <vector>
#include <mutex>
#include <cstdio>
#include <cstring>

#include "../include/amaru_clamwin.h"

// Static variables for ClamAV engine
static struct cl_engine* g_engine = nullptr;
static std::mutex g_engine_mutex;
static std::string g_last_error;
static void (*g_log_callback)(const char* message) = nullptr;

// Helper function to log messages
static void log_message(const char* message) {
    if (g_log_callback) {
        g_log_callback(message);
    }
}

// Convert amaru scan options to clamav scan options
static uint32_t convert_scan_options(const amaru_cw_scan_options_t* options) {
    uint32_t scan_options = 0;
    
    if (options->scan_archives) scan_options |= CL_SCAN_ARCHIVE;
    if (options->scan_mail) scan_options |= CL_SCAN_MAIL;
    if (options->scan_ole2) scan_options |= CL_SCAN_OLE2;
    if (options->scan_pdf) scan_options |= CL_SCAN_PDF;
    if (options->scan_html) scan_options |= CL_SCAN_HTML;
    if (options->scan_pe) scan_options |= CL_SCAN_PE;
    if (options->scan_elf) scan_options |= CL_SCAN_ELF;
    if (options->algorithmic_detection) scan_options |= CL_SCAN_ALGORITHMIC;
    
    return scan_options;
}

extern "C" {

amaru_cw_result_t amaru_cw_init(const char* db_path) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    
    // Initialize if not already initialized
    if (g_engine != nullptr) {
        cl_engine_free(g_engine);
        g_engine = nullptr;
    }
    
    // Initialize ClamAV library
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
        g_last_error = "Failed to initialize ClamAV library";
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_INIT;
    }
    
    // Create new engine
    g_engine = cl_engine_new();
    if (g_engine == nullptr) {
        g_last_error = "Failed to create ClamAV engine";
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_MEMORY;
    }
    
    // Load databases
    unsigned int signature_count = 0;
    int ret = cl_load(db_path, g_engine, &signature_count, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
        g_last_error = std::string("Failed to load database: ") + cl_strerror(ret);
        log_message(g_last_error.c_str());
        cl_engine_free(g_engine);
        g_engine = nullptr;
        return AMARU_CW_ERROR_DATABASE;
    }
    
    // Compile engine
    ret = cl_engine_compile(g_engine);
    if (ret != CL_SUCCESS) {
        g_last_error = std::string("Failed to compile engine: ") + cl_strerror(ret);
        log_message(g_last_error.c_str());
        cl_engine_free(g_engine);
        g_engine = nullptr;
        return AMARU_CW_ERROR_INIT;
    }
    
    char log_buffer[256];
    snprintf(log_buffer, sizeof(log_buffer), "ClamAV engine initialized with %u signatures", signature_count);
    log_message(log_buffer);
    
    return AMARU_CW_SUCCESS;
}

amaru_cw_result_t amaru_cw_scan_file(const char* path, const amaru_cw_scan_options_t* options, amaru_cw_scan_result_t* result) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    
    if (g_engine == nullptr) {
        g_last_error = "ClamAV engine not initialized";
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_INIT;
    }
    
    if (path == nullptr || options == nullptr || result == nullptr) {
        g_last_error = "Invalid parameters";
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_CONFIG;
    }
    
    // Convert scan options
    uint32_t scan_options = convert_scan_options(options);
    
    // Set limits
    cl_engine_set_num(g_engine, CL_ENGINE_MAX_FILESIZE, options->max_filesize * 1024 * 1024);
    cl_engine_set_num(g_engine, CL_ENGINE_MAX_SCANSIZE, options->max_scansize * 1024 * 1024);
    cl_engine_set_num(g_engine, CL_ENGINE_MAX_RECURSION, options->max_recursion);
    cl_engine_set_num(g_engine, CL_ENGINE_MAX_FILES, options->max_files);
    
    // Start time measurement
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Perform scan
    const char* virus_name = nullptr;
    unsigned long scanned = 0;
    int ret = cl_scanfile(path, &virus_name, &scanned, g_engine, scan_options);
    
    // End time measurement
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Fill result
    result->scan_time_ms = duration.count();
    result->filename = path;
    result->is_infected = (ret == CL_VIRUS);
    result->virus_name = (virus_name != nullptr) ? virus_name : "";
    
    // Log result
    char log_buffer[512];
    if (ret == CL_VIRUS) {
        snprintf(log_buffer, sizeof(log_buffer), "Virus found in %s: %s", path, virus_name);
        log_message(log_buffer);
        return AMARU_CW_VIRUS_FOUND;
    } else if (ret == CL_CLEAN) {
        snprintf(log_buffer, sizeof(log_buffer), "No virus found in %s", path);
        log_message(log_buffer);
        return AMARU_CW_SUCCESS;
    } else {
        g_last_error = std::string("Error scanning file: ") + cl_strerror(ret);
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_SCAN;
    }
}

amaru_cw_result_t amaru_cw_scan_memory(const uint8_t* buffer, size_t length, const amaru_cw_scan_options_t* options, amaru_cw_scan_result_t* result) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    
    if (g_engine == nullptr) {
        g_last_error = "ClamAV engine not initialized";
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_INIT;
    }
    
    if (buffer == nullptr || length == 0 || options == nullptr || result == nullptr) {
        g_last_error = "Invalid parameters";
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_CONFIG;
    }
    
    // Convert scan options
    uint32_t scan_options = convert_scan_options(options);
    
    // Start time measurement
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Perform scan
    const char* virus_name = nullptr;
    int ret = cl_scanmap_callback(buffer, length, "memory", &virus_name, nullptr, g_engine, scan_options, nullptr);
    
    // End time measurement
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Fill result
    result->scan_time_ms = duration.count();
    result->filename = "memory buffer";
    result->is_infected = (ret == CL_VIRUS);
    result->virus_name = (virus_name != nullptr) ? virus_name : "";
    
    // Log result
    if (ret == CL_VIRUS) {
        char log_buffer[256];
        snprintf(log_buffer, sizeof(log_buffer), "Virus found in memory: %s", virus_name);
        log_message(log_buffer);
        return AMARU_CW_VIRUS_FOUND;
    } else if (ret == CL_CLEAN) {
        log_message("No virus found in memory buffer");
        return AMARU_CW_SUCCESS;
    } else {
        g_last_error = std::string("Error scanning memory: ") + cl_strerror(ret);
        log_message(g_last_error.c_str());
        return AMARU_CW_ERROR_SCAN;
    }
}

const char* amaru_cw_get_db_version(void) {
    static std::string version;
    
    unsigned int daily_version = 0, main_version = 0;
    const char* result = cl_retdbdir();
    
    if (result == nullptr) {
        g_last_error = "Failed to get database directory";
        log_message(g_last_error.c_str());
        return nullptr;
    }
    
    version = "ClamAV DB: " + std::string(result);
    return version.c_str();
}

amaru_cw_result_t amaru_cw_update_database(const char* db_path) {
    // Not implemented in this version
    g_last_error = "Database update not implemented in core library";
    log_message(g_last_error.c_str());
    return AMARU_CW_ERROR_CONFIG;
}

void amaru_cw_cleanup(void) {
    std::lock_guard<std::mutex> lock(g_engine_mutex);
    
    if (g_engine != nullptr) {
        cl_engine_free(g_engine);
        g_engine = nullptr;
        log_message("ClamAV engine cleaned up");
    }
}

amaru_cw_scan_options_t amaru_cw_default_options(void) {
    amaru_cw_scan_options_t options;
    
    options.scan_archives = true;
    options.scan_mail = true;
    options.scan_ole2 = true;
    options.scan_pdf = true;
    options.scan_html = true;
    options.scan_pe = true;
    options.scan_elf = true;
    options.algorithmic_detection = true;
    options.max_filesize = 100;  // 100 MB
    options.max_scansize = 400;  // 400 MB
    options.max_recursion = 16;
    options.max_files = 10000;
    
    return options;
}

const char* amaru_cw_get_last_error(void) {
    return g_last_error.c_str();
}

void amaru_cw_set_log_callback(void (*callback)(const char* message)) {
    g_log_callback = callback;
}

} // extern "C" 