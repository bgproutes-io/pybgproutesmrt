from pybgproutesmrt.broker import BGProutesMRT

origins = dict()
stream = BGProutesMRT(
    1757300400,
    1757307600,
    "updates",
    peering_protocol="bmp",
    vps=["6939_206.223.118.37|4128_129.250.12.22"])

for msg in stream.get_all_data():
    # if msg.type != "U":
    #     continue

    print(msg)
    # aspath = msg.as_path
    # if not len(aspath):
    #     continue

    # origin = aspath.split(" ")[-1]

    # for prefix in msg.nlri:
    #     origins[prefix] = origin