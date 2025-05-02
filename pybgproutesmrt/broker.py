# SPDX-FileCopyrightText: 2025 Thomas Alfroy
#
# SPDX-License-Identifier: GPL-2.0-only

import requests
import time
import datetime
import json
import os
from requests.exceptions import HTTPError, ConnectionError, Timeout
import ctypes
from ctypes import c_int, c_uint32, c_uint16, c_char, c_void_p, POINTER, Structure


BGPDUMP_MAX_FILE_LEN	= 1024
BGPDUMP_MAX_AS_PATH_LEN	= 2000
MAX_NB_PREFIXES         = 2048
MAX_ATTR                = 4096

BGP_TYPE_ZEBRA_BGP			= 16
BGP_TYPE_ZEBRA_BGP_ET       = 17
BGP_TYPE_TABLE_DUMP_V2      = 13

BGP_SUBTYPE_RIB_IPV4_UNICAST = 2
BGP_SUBTYPE_RIB_IPV6_UNICAST = 4


BGP_TYPE_OPEN               = 1
BGP_TYPE_KEEPALIVE          = 4
BGP_TYPE_UPDATE             = 2
BGP_TYPE_NOTIFICATION       = 3
BGP_TYPE_STATE_CHANGE       = 5


BGPROUTESMRT_LIBRARY_PATH='/usr/local/lib/'


# Import CFRFILE structure from C library
class CFRFILE(Structure):
    _fields_ = [
        ("format", c_int),       # 0 = not open, 1 = uncompressed, 2 = bzip2, 3 = gzip
        ("eof", c_int),          # 0 = not EOF
        ("closed", c_int),       # indicates whether fclose has been called, 0 = not yet
        ("error1", c_int),       # errors from the system, 0 = no error
        ("error2", c_int),       # for error messages from the compressor
        ("data1", c_void_p), # system file handle (FILE *)
        ("data2", c_void_p),     # additional handle(s) for the compressor
        ("bz2_stream_end", c_int) # True when a bz2 stream has ended
    ]


# Import RIB_PEER_INDEX structure from C library
class RIB_PEER_INDEX_T(Structure):
    _fields_ = [
        ("afi", c_int),
        ("idx", c_int),
        ("addr", c_char * 64),
        ("asn", c_uint32)
    ]


class FILE_BUF_T(Structure):
    _fields_ = [
        ("f", POINTER(CFRFILE)),  # Pointer to CFRFILE
        ("f_type", c_int),        # Integer representing the file type
        ("eof", c_int),           # End of file flag
        ("filename", c_char * BGPDUMP_MAX_FILE_LEN),  # Filename array of length BGPDUMP_MAX_FILE_LEN
        ("parsed", c_int),        # Indicates if the file is parsed
        ("parsed_ok", c_int),     # Indicates if the parsing was successful
        ("index", RIB_PEER_INDEX_T * 256),
        ("actPeerIdx", c_int),
        ("actEntry", ctypes.c_void_p)
    ]


class MRT_ENTRY(Structure):
    _fields_ = [
        ("entryType", c_uint16),
        ("entrySubType", c_uint16),
        ("entryLength", c_uint32),
        ("bgpType", c_uint16),
        ("peer_asn", c_uint32),
        ("afi", c_uint16),
        ("peerAddr", c_char * 64),
        ("time", c_uint32),
        ("time_ms", c_uint32),
        ("nbWithdraw", c_uint16),
        ("nbNLRI", c_uint16),
        ("pfxNLRI", c_char * 64 * MAX_NB_PREFIXES),
        ("pfxWithdraw", c_char * 64 * MAX_NB_PREFIXES),
        ("nextHop", c_char * 64),
        ("asPath", c_char * MAX_ATTR),
        ("communities", c_char * MAX_ATTR),
        ("origin", c_char * 16),
        ("dumper", ctypes.POINTER(FILE_BUF_T)),
        ("next", ctypes.c_void_p),
        ("prev", ctypes.c_void_p)
    ]





class BGPmessage:
    """
    Structre that represents a BGP message

    Attributes:
        ts (float): UNIX timestamp at which the BGP message has been collected by the VP.
        type (int): Type of MRT entry (e.g., BGP4MP, BGP4MP_ET, ..)
        nlri (list): List of all prefixes (in string mode) that have been announced in the
        current BGP message.
        withdraws (list): List of all prefixes (in string mode) that have been withdrawn in
        the current BGP message.
        origin (str): String representation of the origin BGP attribute.
        nexthop (str): String representation of the nethop BGP attribute.
        as_path (str): String representation of the AS path BGP attribute.
        communities (str): String representation of the Community values BGP attribute.
        peer_asn (str): AS number of the VP from which we received the message.
        peer_addr (str): String represntation of the IP address of the BGP peer from which
        we received the message.
        msgType (str): String representation of the type of BGP message (e.g., UPDATE, OPEN,...).
        bgpType (int): Integer value of the type of BGP message.
    """
    def __init__(self, mrtentry):
        self.ts          = 0.0
        self.type        = 0
        self.nlri        = list()
        self.withdraws   = list()
        self.origin      = ""
        self.nexthop     = ""
        self.as_path     = ""
        self.communities = ""
        self.peer_asn    = 0
        self.peer_addr   = ""
        self.msgType     = "Unknown"
        self.bgpType     = 0

        self.type = mrtentry.contents.entryType
        self.origin = mrtentry.contents.origin.decode()
        self.as_path = mrtentry.contents.asPath.decode()
        self.communities = mrtentry.contents.communities.decode()
        self.nexthop = mrtentry.contents.nextHop.decode()
        self.ts = mrtentry.contents.time + mrtentry.contents.time_ms / 1000000
        self.peer_asn = mrtentry.contents.peer_asn
        self.peer_addr = mrtentry.contents.peerAddr.decode()
        self.bgpType = mrtentry.contents.bgpType

        # Setup MSG Type
        if self.type == BGP_TYPE_ZEBRA_BGP or self.type == BGP_TYPE_ZEBRA_BGP_ET:
            if self.bgpType == BGP_TYPE_OPEN:
                self.msgType = "O"
            elif self.bgpType == BGP_TYPE_UPDATE:
                self.msgType = "U"
            elif self.bgpType == BGP_TYPE_NOTIFICATION:
                self.msgType = "N"
            elif self.bgpType == BGP_TYPE_KEEPALIVE:
                self.msgType = "K"
            elif self.bgpType == BGP_TYPE_STATE_CHANGE:
                self.msgType = "S"

        elif self.type == BGP_TYPE_TABLE_DUMP_V2:
            self.msgType = "R"


        for i in range(0, mrtentry.contents.nbWithdraw):
            self.withdraws.append(mrtentry.contents.pfxWithdraw[i].value.decode())

        for i in range(0, mrtentry.contents.nbNLRI):
            self.nlri.append(mrtentry.contents.pfxNLRI[i].value.decode())


    
    def __str__(self):
        res = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(self.msgType, self.ts, ",".join(self.nlri), ",".join(self.withdraws), self.origin, self.nexthop, self.as_path, self.communities, self.peer_asn, self.peer_addr)

        return res

mylib = ctypes.CDLL("{}/libbgproutesmrt.so".format(BGPROUTESMRT_LIBRARY_PATH))

mylib.File_buf_create.argtypes = (ctypes.c_char_p,)
mylib.File_buf_create.restype  = ctypes.POINTER(FILE_BUF_T)

mylib.File_buf_close_dump.argtypes = (ctypes.POINTER(FILE_BUF_T),)
mylib.File_buf_close_dump.restype  = None

mylib.Read_next_mrt_entry.argtypes = (ctypes.POINTER(FILE_BUF_T),)
mylib.Read_next_mrt_entry.restype  = ctypes.POINTER(MRT_ENTRY)

mylib.MRTentry_free.argtypes = (ctypes.POINTER(MRT_ENTRY),)
mylib.MRTentry_free.restype  = None



def download_file(url :str, peer :str, timeout):
    """
    Download a BGP dump file from remote GILL's database and store it on local disk.

    Args:
        url (str): URL of the file that need to be donwloaded.
        peer (str): BGP peer from which the downloaded data has been collected
        timeout (int): Number of seconds after which the URL request will be timed out.

    Returns:
        str: The name of the file on which the collected data has been stored on the local
        disk. Returns 'None' in case Exception occured during the downloading.
    """

    ts = url.split("/")[-1].replace(".mrt.bz2", "")
    try:
        response = requests.get(url, stream=True, timeout=timeout)

        if response.status_code != 200:
            return None

        if not os.path.exists("/tmp/bgproutesmrt"):
            os.mkdir("/tmp/bgproutesmrt")

        fn = "/tmp/bgproutesmrt/{}_{}.mrt.bz2".format(peer, ts)

        with open(fn, "wb") as f:
            for chunk in response.iter_content(chunk_size=4096):  # 1KB chunks
                if chunk:
                    f.write(chunk)
        
        return fn

    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return None
    except ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        return None
    except Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
        return None
    except Exception as err:
        print(f"An error occurred: {err}")
        return None



def query_broker(url, timeout):
    """
    Perform a query to the remote GILL file broker.

    Args:
        url (str): URL of the query performed. The URL must contain the required
        endpoint, as well as the correct parameters.
        timeout (int): Number of seconds after which the URL request will be timed out.

    Returns:
        json: Returns a JSON dataframe where each key corresponds to the BGP peer from which 
        we will get the data, and the associated value is the list of files that needs to be
        process for this BGP peer, according to the parameters of the broker request. Returns
        None in case anything wrong happen.
    """

    try:
        response = requests.get(url, stream=True, timeout=timeout)

        if response.status_code != 200:
            return None

        return json.loads(response.content.decode())

    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return None
    except ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        return None
    except Timeout as timeout_err:
        return None
    except Exception as err:
        print(f"An error occurred: {err}")
        return None



def parse_one_file(fn :str):
    """
    Parse a single MRT file and yields every single MRT entry.

    Args:
        fn (str): Name of the file that must be processed. The file can be either compressed 
        or uncompressed.

    Yields:
        BGPmessage: Yields every single MRT entry by transforming them into a BGP message.

    Returns:
        int: return 0 if evrything went well, -1 otherwise.
    """

    dumper = mylib.File_buf_create(fn.encode())

    while dumper.contents.eof == 0:
        entry = mylib.Read_next_mrt_entry(dumper)

        if entry:
            if entry.contents.entryType == BGP_TYPE_ZEBRA_BGP or entry.contents.entryType == BGP_TYPE_ZEBRA_BGP_ET:
                msg = BGPmessage(entry)
                yield msg
            elif entry.contents.entryType == BGP_TYPE_TABLE_DUMP_V2 and \
                (entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST or entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV6_UNICAST):
                msg = BGPmessage(entry)
                yield msg

            #mylib.MRTentry_free(entry)
        
    mylib.File_buf_close_dump(dumper)

    return 0



def date_to_gmt_timestamp(date_str :str):
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    dt = dt.replace(tzinfo=datetime.timezone.utc)  # ensure UTC
    timestamp = int(dt.timestamp())

    return timestamp


class BGProutesMRT:
    """
    Structure representing a Stream of GILL messages.

    Attributes:
        from_time (str, int, float): Time from which we should start getting the data. In case
        this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
        must be a UNIX timestamp.
        until_time (str, int, float): Time from which we should start getting the data. In case
        this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
        must be a UNIX timestamp.
        record_type (str): Specify which type of data must be downloaded. For now, only 'updates'
        and 'ribs' are supported.
        vps (list): Represent the list of Vantage Points from which we want to collect the data.
        Each VP must be of the form 'ASN_IP'. In case this parameter is not set, collect data from
        all VPs.
        all_files (list): List of all files that need to be downloaded to process all required data.
        remaining_files (list): List of files that e still need to process.
        dumper (FILE_BUF_T): Structure of the file dumper.
    """

    def __init__(self, from_time, until_time, record_type :str, vps=None):
        """
        Initialize the Stream of GILL data. Query the broker to know precisely which files
        need to be downloaded and processed.

        Args:
            from_time (str, int, float): Time from which we should start getting the data. In case
            this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
            must be a UNIX timestamp.
            until_time (str, int, float): Time from which we should start getting the data. In case
            this parameter is a string, must be of the form of 'YYYY-MM-DD HH:MM:SS'. Otherwise,
            must be a UNIX timestamp.
            record_type (str): Specify which type of data must be downloaded. For now, only 'updates'
            and 'ribs' are supported.
            vps (list): Represent the list of Vantage Points from which we want to collect the data.
            Each VP must be of the form 'ASN_IP'. In case this parameter is not set, collect data from
            all VPs.
        """
        
        self.from_time = 0
        self.until_time = 0

        self.vps = vps
        self.record_type = record_type

        self.all_files = list()
        self.remaining_files = list()
        self.dumper = None

        self.actFile = None

        if isinstance(from_time, int):
            self.from_time = from_time
        elif isinstance(from_time, float):
            self.from_time = int(from_time)
        elif isinstance(from_time, str):
            try:
                self.from_time = date_to_gmt_timestamp(from_time)
            except:
                print("Date must be on the format 'YYYY-MM-DDTHH:MM:SS'")
                exit(1)

        if isinstance(until_time, int):
            self.until_time = until_time
        elif isinstance(until_time, float):
            self.until_time = int(until_time)
        elif isinstance(until_time, str):
            try:
                self.until_time = date_to_gmt_timestamp(until_time)
            except:
                print("Date must be on the format 'YYYY-MM-DDTHH:MM:SS'")
                exit(1)

        if self.vps:
            http_request = "https://mrt-broker.bgproutes.io/broker?vps={}&from_time={}&until_time={}&data_type={}".format(",".join(self.vps), self.from_time, self.until_time, self.record_type)
        else:
            http_request = "https://mrt-broker.bgproutes.io/broker?from_time={}&until_time={}&data_type={}".format(self.from_time, self.until_time, self.record_type)

        timeout = 1
        data = None

        while data is None and timeout < 128:
            data = query_broker(http_request, timeout)
            timeout *= 2

        if not data:
            print("Unable to join broker, please report the error to 'contact@bgproutes.io'. Error on querying endpoint '{}'.".format(http_request))
            exit(1)

        if "error" in data:
            print("Error from broker: '{}'".format(data["error"]))

        
        for peer in data["files"]:
            for fn in data["files"][peer]:
                self.all_files.append((fn, peer))
                self.remaining_files.append((fn, peer))

        self.all_files = sorted(self.all_files)
        self.remaining_files = sorted(self.remaining_files)

    

    def download_and_open_next_dumper(self):
        """
        Function that close the latest BGP dumper (if any), download the file that must be 
        processed next, and open the corresponding MRT file dumper.
        """

        if self.dumper:
            mylib.File_buf_close_dump(self.dumper)
            self.dumper = None

        if self.actFile:
            os.remove(self.actFile)

        if not len(self.remaining_files):
            return 0
        
        (url, peer) = self.remaining_files.pop(0)

        timeout = 1
        fn = download_file(url, peer, timeout)

        while not fn and timeout < 64:
            timeout *= 2
            fn = download_file(url, peer, timeout)
        
        if not fn:
            print("Skip file {}, unable to download".format(url))
            return 2
        
        self.dumper = mylib.File_buf_create(fn.encode())
        self.actFile = fn

        return 1
    

    def get_all_data(self):
        """
        Function used to get all the data required to process the query. While there
        are some files to be processed, download the new one and yield every BGP message
        contained in the MRT file.

        Yields:
            BGPmessage: Yields every BGP message found in each files reuired to perform the
            query correctly.
        """

        while len(self.remaining_files):
            if not self.dumper or self.dumper.contents.eof != 0:
                ret = self.download_and_open_next_dumper()

                if ret == 0:
                    return
                
                while ret == 2:
                    ret = self.download_and_open_next_dumper()
                    if ret == 0:
                        return
            

            while self.dumper.contents.eof == 0:
                entry = mylib.Read_next_mrt_entry(self.dumper)

                if entry and entry.contents.time >= self.from_time and entry.contents.time <= self.until_time:

                    # If entry is a MRT BGP UPDATE, print it
                    if entry.contents.entryType == BGP_TYPE_ZEBRA_BGP or entry.contents.entryType == BGP_TYPE_ZEBRA_BGP_ET:
                        msg = BGPmessage(entry)
                        yield msg

                    # If entry is a RIB entry, print it as well
                    elif entry.contents.entryType == BGP_TYPE_TABLE_DUMP_V2 and \
                        (entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST or entry.contents.entrySubType == BGP_SUBTYPE_RIB_IPV6_UNICAST):
                        msg = BGPmessage(entry)
                        yield msg

                    #mylib.MRTentry_free(entry)

        if self.dumper:
            mylib.File_buf_close_dump(self.dumper)
            self.dumper = None

        if self.actFile:
            os.remove(self.actFile)



