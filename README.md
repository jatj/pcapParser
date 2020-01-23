# Get flow data

To get the flow data of the pcap we used a tool written on go by Daniel Arndt, [flowtbag](https://github.com/DanielArndt/flowtbag). It was the only tool that allowed us to read in a quick way the pcap file and retrieve the main flow data. To be able to detect which flow is attack or not we also need the start time of the flow. So we modified the flowtbag code to include not only the original [features](https://github.com/DanielArndt/flowtbag/wiki/features), but also the following data at the end:

- **firstTime**(_int64_):  The time of the first packet in the flow
- **flast**(_int64_):  The time of the last packet in the forward direction
- **blast**(_int64_):  The time of the last packet in the backward direction

The tool will generate a text file with a comma separated value of the flow features. 

## Getting flowtbag working: 
- Install golang version 1.11.5 on linux
- Export path `export PATH=$PATH:/usr/lib/go-1.11/bin`
- Run `go get github.com/danielarndt/flowtbag`
- Run on the source folder `go build`
- Parse pcap `./flowtbag AppDDos.pcap > AppDDos.txt` 

## Classifying the raw dataset

If you are using a dataset for classification purposes, you will still need to add the class to each flow. In this repo we used a HTTP DDoS attack dataset from , you can check more of this dataset [here](https://www.unb.ca/cic/datasets/dos-dataset.html) and download it [here](http://205.174.165.80/CICDataset/ISCX-SlowDoS-2016/Dataset/). The dataset provides the times and ips of the hosts that are being attacked and the label of the attack. On the [parser.py](./parser.py) script we read the generated text file from _flowtbag_ [AppDDos.txt](./dataset/AppDDos.txt) and append the corresponding label to each flow. It will write the parsed data into a file named _parsed.txt_ containing each flow and its label at the end.