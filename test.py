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