/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __CIRCULAR_BUFFER_H__
#define __CIRCULAR_BUFFER_H__

#include "cfr_files.h"
#include "mrt_entry.h"
#include "bgp_macros.h"
#include "common.h"
#include "bgproutesmrt-config.h"


#define UPDATE_AND_CHECK_LEN(val, incr, cmp, ret)      \
    val += incr;                            \
    if (val > cmp)                          \
    {                                       \
        return ret;                         \
    }                                       

#define BGPDUMP_MAX_FILE_LEN	1024
#define BGPDUMP_MAX_AS_PATH_LEN	2000

typedef struct 
{
    /**
     * @brief Address Family of the BGP peer.
     */
    int afi;

    /**
     * @brief Index of this peer in the RIB file. The index is used
     * as a pointer in a RIB entry record to know to which peer the
     * entry corresponds.
     */
    int idx;

    /**
     * @brief IP address (in string mode) of the BGP peer.
     */
    char addr[64];

    /**
     * @brief AS number of the BGP peer.
     */
    uint32_t asn;
} rib_peer_index_t;


typedef struct FileBuffer {

    /**
     * @brief Structure corresponding to a bufferized file. The file contained
     * can be either compressed or not.
     */
    CFRFILE	*f;

    /**
     * @brief Type of files from which we will read the data (i.e., comrpessed
     * or not)
     */
    int		f_type;

    /**
     * @brief Defines if there remain some data to read in the file. Has value 0
     * if there are some MRT records remaining in the file, 1 if we finished reading 
     * the file.
     */
    int		eof;

    /**
     * @brief File name in string mode.
     */
    char	filename[BGPDUMP_MAX_FILE_LEN];

    /**
     * @brief Contains the total number of parsed MRT records.
     */
    int		parsed;

    /**
     * @brief Contains the number of MRT records that were prsed without any error.
     */
    int		parsed_ok;

    /**
     * @brief Contains the list of peer index structures (only in case of parsing
     * a RIB dump).
     */
    rib_peer_index_t index[256];

    /**
     * @brief Number of peers currently in the index table.
     */
    int     actPeerIdx;

    /**
     * @brief MRT entry that we are currently reading.
     */
    MRTentry* actEntry;
} File_buf_t;


/**
 * @brief Transform an unsigned character list into a single byte.
 * 
 * @param buf       Pointer to the list of unsigned characters to parse.
 * @return uint8_t Returns the byte value of the first byte of the unsigned character list.
 */

uint8_t get_buf_char(u_char* buf);


/**
 * @brief Transform an unsigned character list into a short integer (2-bytes).
 * 
 * @param buf       Pointer to the list of unsigned characters to parse.
 * @return uint16_t Returns the 2-byte value of the two first bytes of the unsigned character list.
 */

uint16_t get_buf_short(u_char* buf);


/**
 * @brief Transform an unsigned character list into an integer (4-bytes).
 * 
 * @param buf       Pointer to the list of unsigned characters to parse.
 * @return uint16_t Returns the 4-byte value of the four first bytes of the unsigned character list.
 */

uint32_t get_buf_int(u_char* buf);


/**
 * @brief Store the N first bytes of an unsigned character list into another character list.
 * 
 * @param buf       Pointer to the list of unsigned characters to parse.
 * @param dest      Pointer of the character list to which we will write the read characters.
 * @param n         Number of bytes that needs to be read and writen.
 */

void get_buf_n(u_char* buf, char* dest, int n);


/**
 * @brief Creates a File buffer structure. Allocates the required memory and initialize the
 * structure with default parameters. The structure contains multiple utils like a structure
 * to handle read in compressed files, or the index of all the peers in the RIB dump.
 * 
 * The main argument of this function is a file name. This file can be either a compressed or 
 * uncompressed file, but must respect the MRT format. Note that for now only BGP4MP, 
 * BGP4MP_ET, and TABLE_DUMP_V2 MRT types are supported.
 * 
 * @param filename  String corresponding to the file name from which we will extract the data.
 * 
 * @return File_buf_t*  Returns a pointer to the allocated file buffer structure.
 */

File_buf_t* File_buf_create(const char *filename);


/**
 * @brief Free memory allocated for a file buffer structure. Also close the file used to read MRT
 * data from.
 * 
 * @param dump      Pointer to the File buffer structure that needs to be freed. The pointer value
 * of the structure becomes NULL after exiting the function.
 */

void	    File_buf_close_dump(File_buf_t *dump);


/**
 * @brief Read the next MRT record from the corrsponding File buffer structure. In case something
 * wrong happen during the parsing (e.g., parsing issue, unexpected format, unsupported record, ...),
 * the function returns a NULL pointer. In case there is no more data to read in the File buffer
 * structure, dump->eof is set to 1.
 * 
 * @param dump      Pointer to the File buffer structure from which we will read the new MRT entry.
 * 
 * @return MRTentry*    Returns a pointer to a structure containing the newly read MRT entry.
 */

MRTentry*	Read_next_mrt_entry(File_buf_t *dump);


/**
 * @brief Function that processes a MRT entry corresponding to a BGP update record (i.e., either BGP4MP or
 * BGP4MP_ET type). The different parsed values are stored in a MRT entry structure (passed in the
 * arguments as an allocated pointer). The function checks first the consistency of the MRT header, as
 * well as the consistency if the BGP header (e.g., check for BGP marker, type, ...). It then calls 
 * process_bgp_update to parse the content of the BGP message.
 * 
 * @param buffer    Byte array containing the raw MRT entry under its binary representation.
 * @param entry     MRT entry structure that will be filled with the values corresponding to the
 * read MRT entry. Providing an unallocated pointer or a NULL returns a 0 value.
 * @param max_len   Maximum length that we can read in the buffer, i.e., length of the MRT record. 
 * Reading more bytes that this value raises an error (0 return code) as we consider the record 
 * as corrupted.
 * 
 * @return int      Returns 0 if something went wrong when parsing the MRT entry, 1 if everything
 * was parsed correctly
 */

int process_classic_message(u_char* buffer, MRTentry* entry, int max_len);


/**
 * @brief Function that processes a BGP update (header excluded) and writes the corresponding parsed
 * values in a MRT entry structure. It parses the withdraw prefixes, announced prefixes, and then 
 * calls the process_bgp_attributes function. 
 * 
 * @param buffer    Byte array containing the raw BGP update (header excluded)
 * @param entry     MRT entry structure that will be filled with the values corresponding to the
 * read BGP message. Providing an unallocated pointer or a NULL returns a 0 value.
 * @param max_len   Maximum length that we can read in the buffer, i.e., length of the MRT record. 
 * Reading more bytes that this value raises an error (0 return code) as we consider the record 
 * as corrupted.
 * 
 * @return int      Returns 0 if something went wrong when parsing the MRT entry, 1 if everything
 * was parsed correctly
 */

int process_bgp_update(u_char* buffer, MRTentry* entry, int max_len);


/**
 * @brief Function that processes the BGP attributes of a BGP update
 * 
 * @param buffer    Byte array containing the BGP attribute section of the BGP message, in binary
 * representation
 * @param entry     MRT entry structure that will be filled with the values corresponding to the
 * read BGP attributes. Providing an unallocated pointer or a NULL returns a 0 value.
 * @param max_len   Maximum length that we can read in the buffer, i.e., length of the MRT record. 
 * Reading more bytes that this value raises an error (0 return code) as we consider the record 
 * as corrupted.
 * 
 * @return int      Returns 0 if something went wrong when parsing the MRT entry, 1 if everything
 * was parsed correctly
 */

int process_bgp_attributes(u_char* buffer, MRTentry* entry, int max_len);


/**
 * @brief Function used to process a TABLE_DUMP_V2 MRT entry. It fills a MRT entry structure with
 * the corresponding values.
 * 
 * @param buffer    Byte array containing the raw MRT entry corresponding to the RIB entry.
 * @param entry     MRT entry structure that will be filled with the values corresponding to the
 * read BGP attributes. Providing an unallocated pointer or a NULL returns a 0 value.
 * @param max_len   Maximum length that we can read in the buffer, i.e., length of the MRT record. 
 * Reading more bytes that this value raises an error (0 return code) as we consider the record 
 * as corrupted.
 * 
 * @return int      Returns 0 if something went wrong when parsing the MRT entry, 1 if everything
 * was parsed correctly
 */

int process_bgp_rib(u_char* buffer, MRTentry* entry, int max_len);


/**
 * @brief Function used to process an index entry of a TABLE_DUMP_V2 MRT record. It fills a MRT 
 * entry structure, and its related File buffer structure with the corresponding values. The index
 * record contains all the BGP peers that are sharing their BGP routeing table.
 * 
 * @param buffer    Byte array containing the raw MRT record corresponding to the RIB index.
 * @param entry     MRT entry structure that will be filled with the values corresponding to the
 * read BGP attributes. Providing an unallocated pointer or a NULL returns a 0 value.
 * @param max_len   Maximum length that we can read in the buffer, i.e., length of the MRT record. 
 * Reading more bytes that this value raises an error (0 return code) as we consider the record 
 * as corrupted.
 * 
 * @return int      Returns 0 if something went wrong when parsing the MRT entry, 1 if everything
 * was parsed correctly
 */

int process_bgp_rib_index(u_char *buffer, MRTentry* entry, int max_len);


/**
 * @brief Function used to process an RIB entry of a TABLE_DUMP_V2 MRT record. It fills a MRT 
 * entry structure, and its related File buffer structure with the corresponding values. The rib
 * entry consists of a prefix and all associated routes attributes, for all peers that have 
 * visibility over this prefix.
 * 
 * @param buffer    Byte array containing the raw MRT record corresponding to the RIB entry.
 * @param entry     MRT entry structure that will be filled with the values corresponding to the
 * read BGP attributes. Providing an unallocated pointer or a NULL returns a 0 value.
 * @param max_len   Maximum length that we can read in the buffer, i.e., length of the MRT record. 
 * Reading more bytes that this value raises an error (0 return code) as we consider the record 
 * as corrupted.
 * 
 * @return int      Returns 0 if something went wrong when parsing the MRT entry, 1 if everything
 * was parsed correctly
 */

int process_bgp_rib_entry(u_char *buffer, MRTentry* entry, int max_len);



/**
 * @brief Function used to transform a prefix in its binary form into the corresponding string
 * 
 * @param buffer    Binary representation of the prefix.
 * @param string    String in which the prefix value will be stored.
 * @param afi       Address family of the parsed prefix.
 * 
 * @return int      Returns -1 if something went wrong when parsing the MRT entry, length of the
 * output string if everything was parsed correctly
 */

int process_prefix(u_char* buffer, char* string, int afi);


/**
 * @brief Only here for debug purposes.
 */

void print_raw_bgp_message(u_char* buffer, int len, uint16_t type, uint16_t subType);

#endif
