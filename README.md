# pybgproutesmrt

`pybgproutesmrt` is a Python library designed to retrieve BGP (Border Gateway Protocol) data from GILL's database. It provides an interface for downloading BGP updates and routing information based on specified criteria. The library works for both linux and macOS.

## Installation

### Option 1: Using the provided build script

To install the package, clone the repository and run the following commands:

```bash
git clone https://github.com/bgproutes-io/pybgproutesmrt.git
cd pybgproutesmrt
./build_all.sh
```

### Option 2: Manual installation

Alternatively, you can manually compile the C MRT parser and install the package:

```bash
git clone https://github.com/bgproutes-io/pybgproutesmrt.git
cd pybgproutesmrt
cd c_mrt_parser/
autoheader
autoconf
./configure
make
sudo make install
cd ..
python3 -m pip install .
```

In case you want to specify the path where the **libbgpgill.so** file must be installed, use the following commands instead:

```bash
git clone https://github.com/bgproutes-io/pybgproutesmrt.git
cd pybgproutesmrt
cd c_mrt_parser/
autoheader
autoconf
./configure --with-libdir=/my/custom/path/
make
sudo make install
cd ..
GILLSTREAM_LIBRARY_PATH=/my/custom/path/ python3 -m pip install .
```

> **Note:** Ensure you have GCC version 9 or higher before proceeding with the installation.

## Documentation

### C library documentation

You can generate the documentation for the C library by running the following commands:

```bash
cd c_mrt_parser
doxygen Doxyfile
open html/index.html
```

### Python package documentation

You can generate the documentation for the Python package (once it is installed!) by running the following commands:

```bash
python3 -m pip install pdoc
pdoc -d google pybgproutesmrt -o docs
open docs/index.html
```

## Usage

The core component of the package is the `BGProutesMRT` class, which retrieves data from GILL's database based on user-defined time ranges, record types, and vantage points (VPs).

### Class: `BGProutesMRT`

#### Constructor

```python
class BGProutesMRT:
    def __init__(self, from_time, until_time, record_type: str, vps=None):
        self.from_time      = from_time
        self.until_time     = until_time
        self.record_type    = record_type
        self.vps            = vps if vps else []
```

#### Parameters:
- **from_time**: Start time for data retrieval, either as a UNIX timestamp (`float`/`int`) or as a string in the format `'YYYY-MM-DDTHH:MM:SS'`.
- **until_time**: End time for data retrieval, following the same format options as `from_time`.
- **record_type**: Specifies the type of BGP records to retrieve. Valid options are:
  - `'updates'`: For BGP updates.
  - `'ribs'`: For BGP routing information base (RIB) data.
- **vps** (optional): A list of vantage points (VPs) to filter the data. If `None`, data from all VPs will be retrieved. The format for each VP is `'asn_ip'`.

### Method: `get_all_data()`

This method returns an iterator of `BGPmessage` objects, which contain details of each BGP message retrieved.

### Class: `BGPmessage`

```python
class BGPmessage:
    def __init__(self, mrtentry):
        self.ts          = mrtentry['ts']           # Timestamp when the BGP message was received
        self.nlri        = mrtentry['nlri']         # List of prefixes announced in the message
        self.withdraws   = mrtentry['withdraws']    # List of prefixes withdrawn in the message
        self.origin      = mrtentry['origin']       # Origin attribute of the message
        self.nexthop     = mrtentry['nexthop']      # Nexthop attribute of the message
        self.as_path     = mrtentry['as_path']      # AS path attribute of the message
        self.communities = mrtentry['communities']  # Community attribute of the message
        self.peer_asn    = mrtentry['peer_asn']     # ASN of the peer collector
        self.peer_addr   = mrtentry['peerAddr']
```

#### String Representation

The string form of a `BGPmessage` object is formatted as follows:

```python
"{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
    msg.msgType, 
    msg.ts, 
    ",".join(msg.nlri), 
    ",".join(msg.withdraws), 
    msg.origin, 
    msg.nexthop, 
    msg.as_path, 
    msg.communities, 
    msg.peer_asn, 
    msg.peer_addr
)
```

- The leading `U` indicates an update message, the `R` indicates a RIB entry, the `O` indicates an OPEN message, the `N` indicates a NOTIFICATION message, the `K` indicates a Keepalive message, and the `S` indicates a State Change.

## Code Examples

### Example 1: Mapping prefixes to their origin ASN from the Routing tables

To map each prefix with its origin ASN, you can use the following script.

```python
from pybgproutesmrt.broker import BGProutesMRT

origins = dict()
stream = BGProutesMRT(
    "2025-05-02T07:50:00", 
    "2025-05-02T08:10:00", 
    "ribs", 
    vps=["207465_194.147.139.2", "328840_139.84.227.165"])

for msg in stream.get_all_data():
    if msg.type != "R":
        continue

    aspath = msg.as_path
    if not len(aspath):
        continue

    origin = aspath.split(" ")[-1]

    for prefix in msg.nlri:
        origins[prefix] = origin
```

### Example 2: Looking for blackholing communities in BGP updates

To look for BGP updates that announce a blackholing community, use the following script.

```python
from pybgproutesmrt.broker import BGProutesMRT

broker = BGProutesMRT(
    1746204418, 1746206418, "updates"
)

for msg in broker.get_all_data():
    if msg.type != "U":     # Ignore non-update messages
        continue

    if not len(msg.nlri):   # Ignore withdraw messages
        continue

    communities = msg.communities
    if not len(communities):
        continue

    for community in communities.split(" "):
        if ":" not in community:    # Skipp NOEXPORT communities
            continue
        last_short = int(community.split(":")[1])

        if last_short == 666:
            print(msg)
```

### Example 3: Get average NLRI field size from MRT update file

You can use our library to parse single MRT files (only for BGP).

```python
from pybgproutesmrt.broker import parse_one_file
import requests

url = "https://archive.routeviews.org/route-views3/bgpdata/2025.02/UPDATES/updates.20250201.0010.bz2"
response = requests.get(url, stream=True, timeout=timeout)

if response.status_code != 200:
    exit(1)

fn = "/tmp/bgp_update_file.bz2"

with open(fn, "wb") as f:
    for chunk in response.iter_content(chunk_size=4096):  # 1KB chunks
        if chunk:
            f.write(chunk)

cumulated_size = 0
nb_msg = 0

for msg in parse_one_file(fn):
    if msg.type != "U":
        continue

    nb_msg += 1
    cumulated_size += len(msg.nlri)

print(cumulated_size / nb_msg)
```

## Funding

This library is funded through [NGI Zero Core](https://nlnet.nl/core), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/BGP-ForgedOrigin).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/core)
