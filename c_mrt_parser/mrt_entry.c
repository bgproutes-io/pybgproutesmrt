/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "mrt_entry.h"
#include "bgp_macros.h"
#include <stdio.h>
#include <string.h>


#define MAX_BUFF_LEN 4096 * 8


MRTentry* MRTentry_new()
{
    MRTentry* entry = calloc(1, sizeof(MRTentry));

    return entry;
}


MRTentry* MRTentry_copy_for_ribs(MRTentry* entry)
{
    MRTentry* new_ = MRTentry_new();

    new_->dumper       = entry->dumper;
    new_->time         = entry->time;
    new_->time_ms      = entry->time_ms;
    new_->entryType    = entry->entryType;
    new_->entrySubType = entry->entrySubType;
    new_->entryLength  = entry->entryLength;

    for (int i = 0 ; i < entry->nbNLRI ; i++)
    {
        memcpy(new_->pfxNLRI[i], entry->pfxNLRI[i], 64);
    }
    new_->nbNLRI = entry->nbNLRI;

    return new_;
}



void MRTentry_free_one(MRTentry* entry)
{
    free(entry);
}


void MRTentry_free(MRTentry* entry)
{
    MRTentry* tmp = entry;

    while (tmp->prev)
    {
        tmp = tmp->prev;
    }

    MRTentry* tmp2;
    for ( ; tmp ; tmp = tmp2)
    {
        tmp2 = tmp->next;
        MRTentry_free_one(tmp);
    }
}




void MRTentry_print(MRTentry* entry)
{
    int actOff = 0;
    int ret = 0;
    char buffer[MAX_BUFF_LEN];
    memset(buffer, 0, MAX_BUFF_LEN);

    if (entry->entryType == MRT_TYPE_BGP4MP || entry->entryType == MRT_TYPE_BGP4MP_ET)
    {   
        switch (entry->bgpType)
        {
            case BGP_TYPE_OPEN:
                ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "O|");
                actOff += ret;
                break;

            case BGP_TYPE_UPDATE:
                ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "U|");
                actOff += ret;
                break;

            case BGP_TYPE_NOTIFICATION:
                ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "N|");
                actOff += ret;
                break;

            case BGP_TYPE_KEEPALIVE:
                ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "K|");
                actOff += ret;
                break;

            case BGP_TYPE_STATE_CHANGE:
                ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "S|");
                actOff += ret;
                break;
        }
    }
    else
    {
        ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "R|");
        actOff += ret; 
    }

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%d|", entry->time);
    actOff += ret;

    for (int i = 0 ; i < entry->nbNLRI ; i++)
    {
        if (i == entry->nbNLRI-1)
        {
            ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s", entry->pfxNLRI[i]);
            actOff += ret;
        }
        else
        {
            ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s,", entry->pfxNLRI[i]);
            actOff += ret;
        }
    }

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "|");
    actOff += ret; 


    for (int i = 0 ; i < entry->nbWithdraw ; i++)
    {
        if (i == entry->nbWithdraw-1)
        {
            ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s", entry->pfxWithdraw[i]);
            actOff += ret;
        }
        else
        {
            ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s,", entry->pfxWithdraw[i]);
            actOff += ret;
        }
    }

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "|");
    actOff += ret; 

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s|", entry->origin);
    actOff += ret;

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s|", entry->nextHop);
    actOff += ret;

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s|", entry->asPath);
    actOff += ret;

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s|", entry->communities);
    actOff += ret;

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%d|", entry->peer_asn);
    actOff += ret;

    ret = snprintf(buffer+actOff, MAX_BUFF_LEN-actOff, "%s\n", entry->peerAddr);
    actOff += ret;

    printf("%s", buffer);
}