/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "file_buffer.h"
#include "mrt_entry.h"



int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("Please use './bgpgill [file_name]'\n");
        exit(1);
    }

    File_buf_t* dump = File_buf_create(argv[1]);
    MRTentry* entry;

    while (dump->eof==0)
    {
        entry = Read_next_mrt_entry(dump);
        if (entry)
        {
            if (entry->entryType == MRT_TYPE_BGP4MP || entry->entryType == MRT_TYPE_BGP4MP_ET)
            {
                MRTentry_print(entry);
            }
            else if (entry->entryType == MRT_TYPE_TABLE_DUMP_V2)
            {
                if (entry->entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST || entry->entrySubType == BGP_SUBTYPE_RIB_IPV6_UNICAST)
                {
                    MRTentry_print(entry);
                    // if (entry->entrySubType == BGP_SUBTYPE_RIB_IPV6_UNICAST)
                    // {
                    //     MRTentry_print(entry);
                    // }
                }
            }

            //MRTentry_free(entry);
        }
    }

    //printf("PArsed OK: %d\n", dump->parsed_ok);
    File_buf_close_dump(dump);
    return 0;
}

