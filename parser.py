
def parse_flow(rawFlow):
    data = rawFlow.rstrip("\n\r").split(",")
    return {
        "srcip": data[0],
        "srcport": data[1],
        "dstip": data[2],
        "dstport": data[3],
        "proto": data[4],
        "total_fpackets": data[5],
        "total_fvolume": data[6],
        "total_bpackets": data[7],
        "total_bvolume": data[8],
        "min_fpktl": data[9],
        "mean_fpktl": data[10],
        "max_fpktl": data[11],
        "std_fpktl": data[12],
        "min_bpktl": data[13],
        "mean_bpktl": data[14],
        "max_bpktl": data[15],
        "std_bpktl": data[16],
        "min_fiat": data[17],
        "mean_fiat": data[18],
        "max_fiat": data[19],
        "std_fiat": data[20],
        "min_biat": data[21],
        "mean_biat": data[22],
        "max_biat": data[23],
        "std_biat": data[24],
        "duration": data[25],
        "min_active": data[26],
        "mean_active": data[27],
        "max_active": data[28],
        "std_active": data[29],
        "min_idle": data[30],
        "mean_idle": data[31],
        "max_idle": data[32],
        "std_idle": data[33],
        "sflow_fpackets": data[34],
        "sflow_fbytes": data[35],
        "sflow_bpackets": data[36],
        "sflow_bbytes": data[37],
        "fpsh_cnt": data[38],
        "bpsh_cnt": data[39],
        "furg_cnt": data[40],
        "burg_cnt": data[41],
        "total_fhlen": data[42],
        "total_bhlen": data[43],
        "dscp": data[44],
        "firstTime": data[45],
        "flast": data[46],
        "blast": data[47],
        "class": "normal"
    }

def stringify_flow(flow):
    return "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(
        flow["srcip"],
        flow["srcport"],
        flow["dstip"],
        flow["dstport"],
        flow["proto"],
        flow["total_fpackets"],
        flow["total_fvolume"],
        flow["total_bpackets"],
        flow["total_bvolume"],
        flow["min_fpktl"],
        flow["mean_fpktl"],
        flow["max_fpktl"],
        flow["std_fpktl"],
        flow["min_bpktl"],
        flow["mean_bpktl"],
        flow["max_bpktl"],
        flow["std_bpktl"],
        flow["min_fiat"],
        flow["mean_fiat"],
        flow["max_fiat"],
        flow["std_fiat"],
        flow["min_biat"],
        flow["mean_biat"],
        flow["max_biat"],
        flow["std_biat"],
        flow["duration"],
        flow["min_active"],
        flow["mean_active"],
        flow["max_active"],
        flow["std_active"],
        flow["min_idle"],
        flow["mean_idle"],
        flow["max_idle"],
        flow["std_idle"],
        flow["sflow_fpackets"],
        flow["sflow_fbytes"],
        flow["sflow_bpackets"],
        flow["sflow_bbytes"],
        flow["fpsh_cnt"],
        flow["bpsh_cnt"],
        flow["furg_cnt"],
        flow["burg_cnt"],
        flow["total_fhlen"],
        flow["total_bhlen"],
        flow["dscp"],
        flow["firstTime"],
        flow["flast"],
        flow["blast"],
        flow["class"]
    )

def parse_dataset(file, attacks):
    file = open(file, "r")
    flows = []
    first_flow = None

    # Parse flows
    for line in file:
        flow = parse_flow(line)
        if first_flow is None:
            first_flow = flow
        flows.append(flow)

    file.close()

    first_time = int(first_flow["firstTime"])

    file = open("parsed.txt", "w")

    for flow in flows:
        for attack in attacks:
            flow_time = int(flow["firstTime"]) - first_time
            if(flow["dstip"] == attack["dstip"] and attack["time"] < flow_time):
                flow["class"] = attack["class"]
        file.write(stringify_flow(flow))
    
    file.close()


if __name__ == "__main__":
    parse_dataset("./dataset/AppDDos.txt", [
        { "class": "slowbody2", "dstip": "75.127.97.72", "time": 3180},
        { "class": "slowread", "dstip": "75.127.97.72", "time": 7080},
        { "class": "ddossim", "dstip": "75.127.97.72", "time": 8520},
        { "class": "goldeneye", "dstip": "75.127.97.72", "time": 10370},
        { "class": "slowheaders", "dstip": "74.63.40.21", "time": 10797},
        { "class": "rudy", "dstip": "75.127.97.72", "time": 11468},
        { "class": "ddossim", "dstip": "97.74.144.108", "time": 12688},
        { "class": "rudy", "dstip": "208.113.162.153", "time": 12749},
        { "class": "hulk", "dstip": "69.84.133.138", "time": 16958},
        { "class": "slowheaders", "dstip": "67.220.214.50", "time": 21960},
        { "class": "goldeneye", "dstip": "97.74.144.108", "time": 25986},
        { "class": "slowbody2", "dstip": "69.192.24.88", "time": 30073},
        { "class": "slowbody2", "dstip": "97.74.144.108", "time": 33123},
        { "class": "slowbody2", "dstip": "203.73.24.75", "time": 33489},
        { "class": "rudy", "dstip": "97.74.144.108", "time": 34160},
        { "class": "slowread", "dstip": "74.55.1.4", "time": 40382},
        { "class": "slowheaders", "dstip": "97.74.104.201", "time": 41907},
        { "class": "hulk", "dstip": "74.55.1.4", "time": 49593},
        { "class": "hulk", "dstip": "69.192.24.88", "time": 50447},
        { "class": "slowloris", "dstip": "97.74.144.108", "time": 56120},
        { "class": "slowheaders", "dstip": "97.74.144.108", "time": 57767},
        { "class": "slowloris", "dstip": "75.127.97.72", "time": 60573},
        { "class": "slowheaders", "dstip": "75.127.97.72", "time": 63013},
        { "class": "goldeneye", "dstip": "69.192.24.88", "time": 70943},
        { "class": "hulk", "dstip": "75.127.97.72", "time": 71065},
        { "class": "rudy", "dstip": "74.55.1.4", "time": 76799},
    ])