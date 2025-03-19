/**
 * @file amaru_clamwin.h
 * @brief Main header file for Amaru ClamWin integration
 * @copyright Amaru Contributors
 * @license GPL-2.0
 */

#ifndef AMARU_CLAMWIN_H
#define AMARU_CLAMWIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/**
 * Result codes for scan operations
 */
typedef enum {
    AMARU_CW_SUCCESS = 0,          ///< Operation completed successfully
    AMARU_CW_VIRUS_FOUND = 1,      ///< Virus found during scan
    AMARU_CW_ERROR_INIT = -1,      ///< Initialization error
    AMARU_CW_ERROR_SCAN = -2,      ///< Scan error
    AMARU_CW_ERROR_MEMORY = -3,    ///< Memory allocation error
    AMARU_CW_ERROR_OPEN = -4,      ///< File open error
    AMARU_CW_ERROR_DATABASE = -5,  ///< Database error
    AMARU_CW_ERROR_CONFIG = -6     ///< Configuration error
} amaru_cw_result_t;

/**
 * Scan options
 */
typedef struct {
    bool scan_archives;       ///< Scan archives
    bool scan_mail;           ///< Scan mail files
    bool scan_ole2;           ///< Scan OLE2 containers
    bool scan_pdf;            ///< Scan PDF files
    bool scan_html;           ///< Scan HTML
    bool scan_pe;             ///< Scan PE files
    bool scan_elf;            ///< Scan ELF files
    bool algorithmic_detection; ///< Use algorithmic detection
    int32_t max_filesize;     ///< Max file size to scan (in MB)
    int32_t max_scansize;     ///< Max scan size (in MB)
    int32_t max_recursion;    ///< Max recursion level
    int32_t max_files;        ///< Max files to scan
} amaru_cw_scan_options_t;

/**
 * Scan result information
 */
typedef struct {
    const char* virus_name;   ///< Name of virus if found
    const char* filename;     ///< Name of the file
    uint64_t scan_time_ms;    ///< Scan time in milliseconds
    bool is_infected;         ///< Whether the file is infected
} amaru_cw_scan_result_t;

/**
 * Initialize the ClamAV engine
 * @param db_path Path to ClamAV database files
 * @return Result code
 */
amaru_cw_result_t amaru_cw_init(const char* db_path);

/**
 * Scan a file or directory
 * @param path Path to scan
 * @param options Scan options
 * @param result Pointer to result structure
 * @return Result code
 */
amaru_cw_result_t amaru_cw_scan_file(const char* path, const amaru_cw_scan_options_t* options, amaru_cw_scan_result_t* result);

/**
 * Scan a memory buffer
 * @param buffer Buffer to scan
 * @param length Buffer length
 * @param options Scan options
 * @param result Pointer to result structure
 * @return Result code
 */
amaru_cw_result_t amaru_cw_scan_memory(const uint8_t* buffer, size_t length, const amaru_cw_scan_options_t* options, amaru_cw_scan_result_t* result);

/**
 * Get the ClamAV database version
 * @return ClamAV database version string
 */
const char* amaru_cw_get_db_version(void);

/**
 * Update the ClamAV database
 * @param db_path Path to ClamAV database files
 * @return Result code
 */
amaru_cw_result_t amaru_cw_update_database(const char* db_path);

/**
 * Clean up resources
 */
void amaru_cw_cleanup(void);

/**
 * Get default scan options
 * @return Default scan options
 */
amaru_cw_scan_options_t amaru_cw_default_options(void);

/**
 * Get last error message
 * @return Last error message
 */
const char* amaru_cw_get_last_error(void);

/**
 * Set log callback
 * @param callback Function pointer to log callback
 */
void amaru_cw_set_log_callback(void (*callback)(const char* message));

#ifdef __cplusplus
}
#endif

#endif /* AMARU_CLAMWIN_H */ 