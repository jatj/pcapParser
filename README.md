# Get flow data

To get the flow data of the pcap we used, https://github.com/DanielArndt/flowtbag tool, written on go. It was the only tool that allowed us to read in a quick way the pcap file and retrieve the main flow data. To be able to detect which flow is attack or not we also need the start time of the flow. So we modified the flowtbag code to include not only the original [features](https://github.com/DanielArndt/flowtbag/wiki/features), but also the following data at the end:

- **firstTime**(_int64_):  The time of the first packet in the flow
- **flast**(_int64_):  The time of the last packet in the forward direction
- **blast**(_int64_):  The time of the last packet in the backward direction

## Getting flowtbag working: 
- Install golang version 1.11.5 on linux
- Export path `export PATH=$PATH:/usr/lib/go-1.11/bin`
- Run `go get github.com/danielarndt/flowtbag`
- Run on the source folder `go build`
- Parse pcap `./flowtbag AppDDos.pcap > AppDDos.txt`

