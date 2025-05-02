/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "file_buffer.h"


void print_raw_bgp_message(u_char* buffer, int len, uint16_t type, uint16_t subType)
{   
    if (subType != BGP_SUBTYPE_RIB_IPV6_UNICAST)
    {
        return;
    }

    char tmp[1024];
    memset(tmp, 0, 1024);
    printf("\n########## New BGP message ############\n");
    printf("%d | %d\n", type, subType);

    for (int i = 0 ; i < len ; i++)
    {
        printf("%d ", buffer[i]);

        if ((i+1)%16 == 0 && i < len-1)
        {
            printf("\n");
        }
    }
    printf("\n######### End of BGP message ############\n");
}


uint8_t get_buf_char(u_char* buf)
{
    uint8_t ch = buf[0];
    return ch;
}


uint16_t get_buf_short(u_char* buf)
{
    uint16_t ch = 256 * buf[0] + buf[1];

    return ch;
}


uint32_t get_buf_int(u_char* buf)
{
    uint32_t ch = 256 * 256 * 256 * buf[0] + 256 * 256 * buf[1] + 256 * buf[2] + buf[3];
    return ch;
}


void get_buf_n(u_char* buf, char* dest, int n)
{
    for (int i = 0 ; i < n ; i++)
    {
        dest[i] = buf[i];
    }
}



int process_prefix(u_char* buffer, char* string, int afi)
{
    /* Get te prefix length */
    int pfxLen = get_buf_char(buffer);
    
    if (pfxLen > 128)
    {
        return -1;
    }

    int nbBytesPfx = (pfxLen+7)/8;

    /* Get the prefix */
    u_char peer_ip[16];
    u_char tmp_str[52];

    memset(peer_ip, 0, 16);
    get_buf_n(buffer+1, (char*)peer_ip, nbBytesPfx);

    memset(tmp_str, 0, 52);

    if (inet_ntop(afi, peer_ip, (char*)tmp_str, 52) == NULL) 
    {
        return -1;
    }

    /* Write the prefix in string format */
    snprintf(string, 64, "%s/%d", tmp_str, pfxLen);

    return 1+nbBytesPfx;
}


File_buf_t* File_buf_create(const char *filename)
{
    File_buf_t* dumper = calloc(1, sizeof(File_buf_t));
    dumper->f = cfr_open(filename);

    if (!dumper->f)
    {
        printf("Unable to open file %s\n", filename);
        free(dumper);
        return NULL;
    }

    dumper->eof=0;
    dumper->parsed = 0;
    dumper->parsed_ok = 0;

    return dumper;
}


void File_buf_close_dump(File_buf_t *dump)
{
    if(dump == NULL) {
        return;
    }

    if (dump->actEntry)
    {
        MRTentry_free(dump->actEntry);
    }

	cfr_close(dump->f);
    free(dump);
}



MRTentry* Read_next_mrt_entry(File_buf_t *dump)
{   
    MRTentry* tmp;
    /* In case we read something at the previous iteration */
    if (dump->actEntry)
    {
        /* If there is still a next entry that has not been already read */
        if (dump->actEntry->next)
        {
            tmp = dump->actEntry->next;
            dump->actEntry = dump->actEntry->next;
            return tmp;
        }
        /* If there is nothing left to read, free all entries */
        else
        {
            MRTentry_free(dump->actEntry);
        }
    }

    MRTentry* entry = MRTentry_new();
    entry->dumper = dump;

    if (!entry)
    {
        printf("Unable to allocate any memory\n");
        dump->actEntry = NULL;
        return NULL;
    }

    u_int32_t bytes_read;
    u_int8_t ok=0;
    u_int8_t* bgpMsgBuffer;

    bytes_read = cfr_read_n(dump->f, &entry->time, 4);
    bytes_read += cfr_read_n(dump->f, &(entry->entryType), 2);
    bytes_read += cfr_read_n(dump->f, &(entry->entrySubType), 2);
    bytes_read += cfr_read_n(dump->f, &(entry->entryLength), 4);

    if (bytes_read == 12) 
    {
        /* Intel byte ordering stuff ... */
        entry->entryType = ntohs(entry->entryType);
        entry->entrySubType = ntohs(entry->entrySubType);
        entry->time = (time_t) ntohl (entry->time);
        entry->entryLength = ntohl(entry->entryLength);
        
        /* If Extended Header format, then reading the miscroseconds attribute */
        if (entry->entryType == MRT_TYPE_BGP4MP_ET) 
        {
            bytes_read += cfr_read_n(dump->f, &(entry->time_ms), 4);
            if (bytes_read == 16) 
            {
                entry->time_ms = ntohl(entry->time_ms);
                /* "The Microsecond Timestamp is included in the computation of
                 * the Length field value." (RFC6396 2011) */
                entry->entryLength -= 4;
                ok = 1;
            }
        } 
        else 
        {
            entry->time_ms = 0;
            ok = 1;
        }
    }


    if (!ok) 
    {
        if(bytes_read > 0) 
        {
            /* Malformed record */
            printf("Incomplete MRT header (%d bytes read, expecting 12 or 16)\n", bytes_read);
        }
        /* Nothing more to read, quit */
        MRTentry_free(entry);
        dump->eof = 1;
        dump->actEntry = NULL;
        return(NULL);
    }

    dump->parsed++;

    if(entry->entryLength == 0) 
    {
        printf("Iinvalid entry length: 0\n");
        MRTentry_free(entry);
        dump->eof = 1;
        dump->actEntry = NULL;
        return(NULL);
    }

    if ((bgpMsgBuffer = malloc(entry->entryLength)) == NULL) 
    {
        printf("Out of memory\n");
        MRTentry_free(entry);
        dump->eof = 1;
        dump->actEntry = NULL;
        return(NULL);
    }

    bytes_read = cfr_read_n(dump->f, bgpMsgBuffer, entry->entryLength);

    if(bytes_read != entry->entryLength) 
    {
	    printf("Incomplete dump record (%d bytes read, expecting %d)\n", bytes_read, entry->entryLength);
        MRTentry_free(entry);
        free(bgpMsgBuffer);
        dump->eof = 1;
        dump->actEntry = NULL;
        return(NULL);
    }

    switch(entry->entryType) 
    {
        case MRT_TYPE_BGP4MP:
        case MRT_TYPE_BGP4MP_ET:
            ok = process_classic_message(bgpMsgBuffer, entry, entry->entryLength);
            break;

        case MRT_TYPE_TABLE_DUMP_V2:
            ok = process_bgp_rib(bgpMsgBuffer, entry, entry->entryLength);
            break;
        
        default:
            printf("Sorry MRT type not handled\n");
            break;
    }

    free(bgpMsgBuffer);

    if(ok) 
    {
	    dump->parsed_ok++;
    } 
    else 
    {
        MRTentry_free(entry);
        dump->actEntry = NULL;
        return NULL;
    }

    dump->actEntry = entry;
    return entry;
}



int process_classic_message(u_char* buffer, MRTentry* entry, int max_len)
{
    if (!entry || !buffer)
    {
        return 0;
    }

    u_char marker[16]; /* BGP marker */
    int actOff = 0;
    u_char peer_ip[16];
    uint16_t msgSize;
    u_char msgType;

    /* In case we have an ASN 2-bytes peer */
    if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE || 
        entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_LOCAL || 
        entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE)
    {
        /* Get the peer ASN */
        entry->peer_asn = get_buf_short(buffer + actOff);
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 

        /* Skip dest ASN */
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 
    }
    /* In case we have an ASN 4-bytes peer */
    else if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_AS4 || 
             entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL ||
             entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE_AS4)
    {
        /* Get the peer ASN */
        entry->peer_asn = get_buf_int(buffer + actOff);
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 

        /* Skip dest ASN */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 
    }
    else
    {
        return 0;
    }

    /* Skip interface ID */
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 
    
    /* Get the peer AFI */
    entry->afi = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 

    /* Set the number of prefixes to 0 */
    entry->nbNLRI = 0;
    entry->nbWithdraw = 0;

    /* Parsing source peer IP */
    if (entry->afi == BGP_IPV4_AFI)
    {
        get_buf_n(buffer+actOff, (char*)peer_ip, 4);
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 

        /* Skip destination IP */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

        if (inet_ntop(AF_INET, peer_ip, entry->peerAddr, 64) == NULL) 
        {
            return 0;
        }
    }
    else if (entry->afi == BGP_IPV6_AFI)
    {
        get_buf_n(buffer+actOff, (char*)peer_ip, 16);
        UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0) 

        /* Skip destination IP */
        UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0) 

        if (inet_ntop(AF_INET6, peer_ip, entry->peerAddr, 64) == NULL) 
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE ||
        entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE_AS4)
    {
        entry->bgpType = BGP_TYPE_STATE_CHANGE;

        /* Skipp old state */
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

        /* skipp new state */
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

        return 1;
    }

    /* Get BGP marker */
    get_buf_n(buffer+actOff, (char*)marker, 16);
    UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0)

    /* If BGP marker is not correct, return */
    if(memcmp(marker, "\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377", 16) != 0)
    {
        return 0;
    }

    /* Get BGP message Length */
    msgSize = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    /* Check for message length inconsistency */
    if (msgSize + actOff - 18 !=max_len)
    {
        printf("BGP message inconsistency %d vs %d\n", msgSize + actOff - 18, max_len);
        return 0;
    }

    /* Get Message type */
    msgType = get_buf_char(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 1, max_len, 0)

    switch (msgType)
    {
        case BGP_TYPE_UPDATE:
            entry->bgpType = BGP_TYPE_UPDATE;
            return process_bgp_update(buffer+actOff, entry, msgSize - 19);

        default:
            entry->bgpType = msgType;
            return 1;
    }

    return 1;
}


int process_bgp_update(u_char* buffer, MRTentry* entry, int max_len)
{
    int actOff = 0;
    int ret;
    int parsedLen = 0;

    /* Get the withdraw length */
    uint16_t withdrawLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    uint16_t actWithLen = 0;


    /* parsing withdraw section */
    while (actWithLen < withdrawLen)
    {   
        /* If already too much prefixes in the packet, just skip */
        if (entry->nbWithdraw >= MAX_NB_PREFIXES)
        {
            parsedLen = get_buf_char(buffer+actOff);
            if (parsedLen > 128)
            {
                return 0;
            }
            parsedLen = (parsedLen+7)/8;

            UPDATE_AND_CHECK_LEN(actOff, parsedLen+1, max_len, 0)
        }
        else
        {
            /* Get te prefix length */
            parsedLen = process_prefix(buffer+actOff, entry->pfxWithdraw[entry->nbWithdraw], AF_INET);
            if (parsedLen == -1)
            {
                return 0;
            }

            UPDATE_AND_CHECK_LEN(actOff, parsedLen, max_len, 0)
            actWithLen += parsedLen;
            
            entry->nbWithdraw++;
        }
        
    }

    /* Get all attribute length */
    uint16_t allAttrLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    ret = process_bgp_attributes(buffer+actOff, entry, allAttrLen);
    if (ret != allAttrLen)
    {
        return 0;
    }

    actOff += allAttrLen;

    /* Parse IPv4 NLRI */
    while (actOff < max_len)
    {
        /* If already too much prefixes in the packet, just skip them */
        if (entry->nbNLRI >= MAX_NB_PREFIXES)
        {
            parsedLen = get_buf_char(buffer+actOff);
            if (parsedLen > 128)
            {
                return 0;
            }
            parsedLen = (parsedLen+7)/8;

            UPDATE_AND_CHECK_LEN(actOff, parsedLen+1, max_len, 0)
        }
        else
        {
            ret = process_prefix(buffer+actOff, entry->pfxNLRI[entry->nbNLRI], AF_INET);
            if (ret == -1)
            {
                return 0;
            }

            UPDATE_AND_CHECK_LEN(actOff, ret, max_len, 0)
            entry->nbNLRI++;
        }
    }

    return 1;
}



int process_bgp_rib(u_char* buffer, MRTentry* entry, int max_len)
{
    
    switch (entry->entrySubType)
    {
        case BGP_SUBTYPE_PEER_INDEX_TABLE:
            return process_bgp_rib_index(buffer, entry, max_len);

        case BGP_SUBTYPE_RIB_IPV4_UNICAST:
        case BGP_SUBTYPE_RIB_IPV6_UNICAST:
            return process_bgp_rib_entry(buffer, entry, max_len);
        default:
            return 0;
    }
}






int process_bgp_rib_index(u_char *buffer, MRTentry* entry, int max_len)
{
    int actOff = 0;
    uint16_t viewLen;
    uint16_t peerCount;
    uint8_t peerType;
    uint32_t peerIdx;

    /* Collector ID */
    UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 

    /* Get the view length */
    viewLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    /* Skip View name if exists */
    UPDATE_AND_CHECK_LEN(actOff, viewLen, max_len, 0)

    /* Get the peer count */
    peerCount = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    for (int i = 0 ; i < peerCount ; i++)
    {
        /* Get peer Type */
        peerType = get_buf_char(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 1, max_len, 0)
        
        /* Skip peer ID */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
        peerIdx = entry->dumper->actPeerIdx;
        entry->dumper->actPeerIdx++;

        if (peerIdx < 256)
        {
            entry->dumper->index[peerIdx].afi = peerType;
            entry->dumper->index[peerIdx].idx = peerIdx;

            if (peerType & 0x01) /* Case IPv6 peer */
            {
                /* Get peer IP address */
                if (inet_ntop(AF_INET6, buffer+actOff, entry->dumper->index[peerIdx].addr, 64) == NULL) 
                {
                    return 0;
                }
                UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0)
            }
            else /* Case IPv4 peer */
            {
                /* Get peer IP address */
                if (inet_ntop(AF_INET, buffer+actOff, entry->dumper->index[peerIdx].addr, 64) == NULL) 
                {
                    return 0;
                }
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }

            if (peerType & 0x02) /* Case ASN-32 peer */
            {
                /* Get peer ASN */
                entry->dumper->index[peerIdx].asn = get_buf_int(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }
            else /* Case ASN-16 peer */
            {
                /* Get peer ASN */
                entry->dumper->index[peerIdx].asn = get_buf_short(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)
            }

        }
        /* Just skip if to much IDs */
        else
        {
            if (peerType & 0x01) /* Case IPv6 peer */
            {
                /* Skipp peer IP address */
                UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0)
            }
            else /* Case IPv4 peer */
            {
                /* Skipp peer IP address */
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }

            if (peerType & 0x02) /* Case ASN-32 peer */
            {
                /* Skipp peer ASN */
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }
            else /* Case ASN-16 peer */
            {
                /* Skipp peer ASN */
                UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)
            }
        }
    }

    return 1;
}

int process_bgp_rib_entry(u_char *buffer, MRTentry* entry, int max_len)
{
    int actOff = 0;
    int ret;
    uint16_t nbEntries;
    uint16_t peerIdx;
    uint16_t attrLen;

    /* Skip sequence number */
    UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

    /* Process prefix */
    if (entry->entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST)
    {
        ret = process_prefix(buffer+actOff, entry->pfxNLRI[entry->nbNLRI++], AF_INET);
    }
    else
    {
        ret = process_prefix(buffer+actOff, entry->pfxNLRI[entry->nbNLRI++], AF_INET6);
    }

    if (ret == -1)
    {
        return 0;
    }
    UPDATE_AND_CHECK_LEN(actOff, ret, max_len, 0)

    /* Get the number of entries */
    nbEntries = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    /* Process only the first RIB entry, skip other if exists */
    peerIdx = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)


    /* If peer Index is too long, skip */
    if (peerIdx >= 256)
    {
        return 0;
    }

    /* Setup the peer infos according to index */
    entry->peer_asn = entry->dumper->index[peerIdx].asn;
    memcpy(entry->peerAddr, entry->dumper->index[peerIdx].addr, 32);

    /* Skip timestamp (already in MRT header) */
    UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

    /* Get attribute length */
    attrLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0);

    /* Process attributes */
    ret = process_bgp_attributes(buffer+actOff, entry, attrLen);
    if (ret != attrLen)
    {
        return 0;
    }

    UPDATE_AND_CHECK_LEN(actOff, attrLen, max_len, 0);
    MRTentry* tmpEntry;
    MRTentry* prevEntry = entry;

    /* Skip other entries */
    for (int i = 1 ; i < nbEntries ; i++)
    {
        tmpEntry = MRTentry_copy_for_ribs(entry);
        tmpEntry->prev = prevEntry;
        prevEntry->next = tmpEntry;

        /* Process only the first RIB entry, skip other if exists */
        peerIdx = get_buf_short(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)


        /* If peer Index is too long, skip */
        if (peerIdx >= 256)
        {
            return 0;
        }

        /* Setup the peer infos according to index */
        tmpEntry->peer_asn = entry->dumper->index[peerIdx].asn;
        memcpy(tmpEntry->peerAddr, entry->dumper->index[peerIdx].addr, 32);

        /* Skip timestamp */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

        /* Get Attribute length */
        attrLen = get_buf_short(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

        /* Process attributes */
        ret = process_bgp_attributes(buffer+actOff, tmpEntry, attrLen);
        if (ret != attrLen)
        {
            return 0;
        }

        UPDATE_AND_CHECK_LEN(actOff, attrLen, max_len, 0)

        prevEntry = tmpEntry;
    }

    return 1;
}



int process_bgp_attributes(u_char* buffer, MRTentry* entry, int allAttrLen)
{
    uint32_t actOff = 0;
    uint16_t actAllAttrLen = 0;
    uint8_t attrFlags, attrType;
    uint16_t attrLen;
    uint32_t asn, com;
    uint32_t aspActStrLen = 0;
    uint32_t comActStrlen = 0;
    int ret;
    int parsedLen;
    uint8_t val;
    uint8_t segType;
    uint8_t segLen;
    uint8_t nextHopLen;
    uint8_t isMRTcompressed;


    while (actAllAttrLen < allAttrLen)
    {   
        /* Get attribute flags */
        attrFlags = get_buf_char(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0);
        actAllAttrLen += 1;

        /* Get attribute type */
        attrType = get_buf_char(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0);
        actAllAttrLen += 1;

        /* Retrieve attribute Length */
        if (attrFlags & 0x10)
        {
            /* If extended lenth is set */
            attrLen = get_buf_short(buffer+actOff);
            UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0);
            actAllAttrLen += 2;
        }
        else
        {
            /* If extended length is not set */
            attrLen = get_buf_char(buffer+actOff);
            UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)
            actAllAttrLen += 1;
        }

        /* Check attribute length */
        if (attrLen > 4096)
        {
            return 0;
        }

        /* Switch attribute type */
        switch (attrType)
        {
            case BGP_UPDATE_ATTR_ORIGIN:
                /* Get origin value */
                val = get_buf_char(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)

                if (val == BGP_UPDATE_ORIGIN_IGP)
                {
                    snprintf(entry->origin, 16, "IGP");
                }
                else if (val == BGP_UPDATE_ORIGIN_EGP)
                {
                    snprintf(entry->origin, 16, "EGP");
                }
                else if (val == BGP_UPDATE_ORIGIN_INCOMPLETE)
                {
                    snprintf(entry->origin, 16, "INCOMPLETE");
                }
                else
                {
                    snprintf(entry->origin, 16, "UNKNOWN");
                }

                break;

            /* Parsing the AS path */
            case BGP_UPDATE_ATTR_AS_PATH:
                segType   = 0;
                segLen    = 0;
                parsedLen = 0;

                /* While we did not parse the entire AS path */
                while (parsedLen < attrLen)
                {   

                    segType = get_buf_char(buffer+actOff);
                    UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)

                    segLen = get_buf_char(buffer+actOff);
                    UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)


                    parsedLen += 2;

                    /* Swicth AS path segment type */
                    switch (segType)
                    {   
                        /* In case of an AS sequence */
                        case BGP_UPDATE_AS_PATH_SEQ:
                            /* AS seq */
                            for (int i = 0 ; i < segLen ; i++)
                            {
                                // Parse the ASN
                                if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE || entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_LOCAL)
                                {
                                    asn = get_buf_short(buffer+actOff);
                                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)
                                    parsedLen += 2;
                                }
                                else
                                {
                                    asn = get_buf_int(buffer+actOff);
                                    UPDATE_AND_CHECK_LEN(actOff, 4, allAttrLen, 0)
                                    parsedLen += 4;
                                }
                                
                                
                                /* Do not add a extra space if last element of the AS-path */
                                if (parsedLen == attrLen)
                                {
                                    ret = snprintf(entry->asPath+aspActStrLen, MAX_ATTR - aspActStrLen, "%u", asn);
                                }
                                else
                                {
                                    ret = snprintf(entry->asPath+aspActStrLen, MAX_ATTR - aspActStrLen, "%u ", asn);
                                }
                                
                                if (ret < 0)
                                {
                                    return 0;
                                }

                                aspActStrLen += ret;
                                if (aspActStrLen >= MAX_SEND_BUFF)
                                {
                                    return 0;
                                }
                            }
                            break;

                        /* Case of an AS set */
                        case BGP_UPDATE_AS_PATH_SET:
                            /* AS Set */
                            ret = snprintf(entry->asPath+aspActStrLen, MAX_ATTR - aspActStrLen, "{");
                            if (ret < 0)
                            {
                                return 0;
                            }

                            aspActStrLen += ret;
                            if (aspActStrLen >= MAX_SEND_BUFF)
                            {
                                return 0;
                            }

                            for (int i = 0 ; i < segLen ; i++)
                            {
                                if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE || entry->entrySubType ==MRT_SUBTYPE_BGP4MP_MESSAGE_LOCAL)
                                {
                                    asn = get_buf_short(buffer+actOff);
                                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)
                                    parsedLen += 2;
                                }
                                else
                                {
                                    asn = get_buf_int(buffer+actOff);
                                    UPDATE_AND_CHECK_LEN(actOff, 4, allAttrLen, 0)
                                    parsedLen += 4;
                                }

                                ret = snprintf(entry->asPath+aspActStrLen, MAX_SEND_BUFF-aspActStrLen, "%u", asn);
                                if (ret < 0)
                                {
                                    return 0;
                                }

                                aspActStrLen += ret;
                                if (aspActStrLen >= MAX_SEND_BUFF)
                                {
                                    return 0;
                                }

                                if (i < segLen-1)
                                {
                                    ret = snprintf(entry->asPath+aspActStrLen, MAX_SEND_BUFF-aspActStrLen, ",");
                                    if (ret < 0)
                                    {
                                        return 0;
                                    }

                                    aspActStrLen += ret;
                                    if (aspActStrLen >= MAX_SEND_BUFF)
                                    {
                                        return 0;
                                    }
                                }
                            }

                            ret = snprintf(entry->asPath+aspActStrLen, MAX_SEND_BUFF-aspActStrLen, "}");
                            if (ret < 0)
                            {
                                return 0;
                            }

                            aspActStrLen += ret;
                            if (aspActStrLen >= MAX_SEND_BUFF)
                            {
                                return 0;
                            }

                            break;

                        default:
                            break;

                    }
                }
                break;

            /* Parse the BGP communities */
            case BGP_UPDATE_NLRI_COMMUNITIES:
                parsedLen = 0;
                while (parsedLen < attrLen)
                {   
                    /* Get the first 2 bytes */
                    asn = get_buf_short(buffer+actOff);
                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)
                    parsedLen += 2;

                    /* Get the second part of the communities */
                    com = get_buf_short(buffer+actOff);
                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)
                    parsedLen += 2;

                    /* Do not add extra space if end of community set */
                    if (parsedLen == attrLen)
                    {
                        ret = snprintf(entry->communities+comActStrlen, MAX_ATTR-comActStrlen, "%d:%d", asn, com);
                    }
                    else
                    {
                        ret = snprintf(entry->communities+comActStrlen, MAX_ATTR-comActStrlen, "%d:%d ", asn, com);
                    }
                    
                    if (ret < 0)
                    {
                        return -1;
                    }

                    comActStrlen += ret;
                    if (comActStrlen >= MAX_ATTR)
                    {
                        return -1;
                    }
                }
                break;

            /* Parse the nexthop attribute */
            case BGP_UPDATE_ATTR_NEXT_HOP:

                /* Check that the Next-hop is 4-bytes long, return otherwise */
                if (attrLen != 4)
                {
                    UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)
                    return 0;
                }

                if (inet_ntop(AF_INET, buffer+actOff, entry->nextHop, 64) == NULL) 
                {
                    return 0;
                }

                UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)

                break;

            /* Parse MP NRLI REACH, i.e., parse IPv6 nexthop and prefixes */
            case BGP_UPDATE_ATTR_NLRI:
                parsedLen = 0;

                /* In case we are not in a shortened MRT MP reach */
                if (buffer[actOff] != 0)
                {
                    isMRTcompressed = true;
                }
                else
                {
                    isMRTcompressed = false;
                }
                

                if (!isMRTcompressed)
                {
                    /* Skip AFI */
                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)

                    /* Skip SAFI */
                    UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)
                }

                /* Get length of nexthop */
                nextHopLen = get_buf_char(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)

                /* Get string for IPv6 nexthop address */
                if (inet_ntop(AF_INET6, buffer+actOff, entry->nextHop, 64) == NULL) 
                {
                    return 0;
                }

                UPDATE_AND_CHECK_LEN(actOff, nextHopLen, allAttrLen, 0);

                if (isMRTcompressed)
                {
                    parsedLen = 1 + nextHopLen;
                }
                else
                {
                    /* Skip nb attached layers */
                    UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0);
                    parsedLen = 5 + nextHopLen;
                }
                

                while (parsedLen < attrLen)
                { 
                    /* Get the prefix length */
                    ret = process_prefix(buffer+actOff, entry->pfxNLRI[entry->nbNLRI], AF_INET6);
                    if (ret == -1)
                    {
                        return 0;
                    }

                    UPDATE_AND_CHECK_LEN(actOff, ret, allAttrLen, 0)
                    parsedLen += ret;
                    
                    entry->nbNLRI++;
                }
                break;

            /* Case of IPv6 withdraw */
            case BGP_UPDATE_NLRI_UNREACH:
                parsedLen = 0;

                /* Skip AFI */
                UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)

                /* Skip SAFI */
                UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)

                parsedLen = 3;

                while (parsedLen < attrLen)
                {
                    /* Get te prefix length */
                    ret = process_prefix(buffer+actOff, entry->pfxWithdraw[entry->nbWithdraw], AF_INET6);
                    if (ret == -1)
                    {
                        return 0;
                    }

                    UPDATE_AND_CHECK_LEN(actOff, ret, allAttrLen, 0)
                    parsedLen += ret;
                    
                    entry->nbWithdraw++;
                }

                break;

            /* Default case for unknown or OSEF attribute */
            default:
                UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0);
        }

        actAllAttrLen += attrLen;
    }

    return actOff;
}
