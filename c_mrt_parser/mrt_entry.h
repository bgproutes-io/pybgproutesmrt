/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __MRT_ENTRY_H__
#define __MRT_ENTRY_H__

#include <stdlib.h>

#define MAX_NB_PREFIXES 2048

#define MAX_ATTR 4096


/**
 * @brief Structure containing an IP prefix.
 */
typedef struct
{
    /**
     * @brief Address family of the IP prefix.
     */
    u_int8_t afi;

    /**
     * @brief Length of the prefix mask.
     */
    u_int8_t pfxLen;

    /**
     * @brief Array of bytes composing the prefix (4 for IPv4, 16 for IPv6).
     */
    u_int8_t pfx[16];
} Prefix_t;


struct FileBuffer;

/**
 * @brief Structure representing a MRT entry (only for BGP-related records.). Most
 * of the fields are in a human-readable format.
 */
typedef struct mrt_entry_t
{
    /**
     * @brief Entry type of the MRT entry, as defined in the RFC.
     */
    u_int16_t entryType;

    /**
     * @brief Entry subtype of the MRT entry, as defined in the RFC.
     */
    u_int16_t entrySubType;

    /**
     * @brief Length of the MRT entry (in number of bytes).
     */
    u_int32_t entryLength;


    /**
     * @brief Type of BGP message (e.g., UPDATE, KEEPALIVE,...). We also added the
     * BGP STATE CHANGE message, in case we have an MRT state change message.
     */
    u_int16_t bgpType;


    /**
     * @brief AS number of the BGP peer from which we collected the BGP message
     */
    u_int32_t peer_asn;

    /**
     * @brief Address family of the BGP peer from which we collected the BGP message
     */
    u_int16_t afi;

    /**
     * @brief IP addess of the BGP peer. The address is stored in string mode.
     */
    char peerAddr[64];

    /**
     * @brief UNIX timestamp at which the BGP message as been received. Represents
     * only the number of second
     */
    u_int32_t time;

    /**
     * @brief UNIX timestamp at which the BGP message as been received. Represents
     * only the number of MilliSeconds (without the seconds).
     */
    u_int32_t time_ms;


    /**
     * @brief Number of prefixes that are withdrawn in this BGP message (if any).
     */
    u_int16_t nbWithdraw;

    /**
     * @brief Number of prefixes that are announced in this BGP message (if any).
     */
    u_int16_t nbNLRI;


    /**
     * @brief List of prefixes that are announced in this BGP message. Each prefix 
     * is stored in string representation.
     */
    char pfxNLRI[MAX_NB_PREFIXES][64];

    /**
     * @brief List of prefixes that are withdrawn in this BGP message. Each prefix 
     * is stored in string representation.
     */
    char pfxWithdraw[MAX_NB_PREFIXES][64];


    /**
     * @brief IP of the next hop attribute value. The IP is stored in string mode.
     */
    char nextHop[64];

    /**
     * @brief AS path attribute value announced in this BGP message. The AS path is
     * stored in string mode.
     */
    char asPath[MAX_ATTR];

    /**
     * @brief Community attribute values announced in this BGP message. The community
     * values are stored in string mode.
     */
    char communities[MAX_ATTR];

    /**
     * @brief Origin attribute value announced in this BGP message. The origin is stored
     * in string mode.
     */
    char origin[16];


    /**
     * @brief Related File buffer structure.
     */
    struct FileBuffer* dumper;

    struct mrt_entry_t *next;
    struct mrt_entry_t *prev;

} MRTentry;


/**
 * @brief Function that creates a new, enmpty pointer to an allocated MRT entry
 * structure. In case no memory can be allocated, NULL is returned.
 * 
 * @return MRTentry*    Returns the pointer to the allocated new MRT entry structure.
 */
MRTentry* MRTentry_new(void);


/**
 * @brief Function that copy an MRT entry. Takes an input MRT entry, creates a new pointer
 * to an allocated empty MRT structure, and copy the content of the input one to the newly
 * created one.
 * 
 * @param entry     Pointer to the MRT entry structure that we want to copy.
 * 
 * @return MRTentry*    Returns a pointer to the copied MRT entry.
 */

MRTentry* MRTentry_copy_for_ribs(MRTentry* entry);


/**
 * @brief Function that frees the current MRT entry. Does not touch anything to the MRT entry
 * structures that are linked to the current one.
 * 
 * @param entry     Pointer to the MRT entry structure that we want to free.
 */

void MRTentry_free_one(MRTentry* entry);


/**
 * @brief Function that frees the current MRT entry structre, as well as all the other MRT entries
 * that are linked to the current one.
 * 
 * @param entry     Pointer to the MRT entry structure that we want to free.
 */
void MRTentry_free(MRTentry* entry);


/**
 * @brief Function that print (on standard output) the corresponding full MRT entry.
 * 
 * @param entry     Pointer to the MRT entry that we want to print.
 */
void MRTentry_print(MRTentry* entry);

#endif