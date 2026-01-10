# boofuzz-can
Implementation of a fuzzing system for the ICSim example using the Boofuzz framework

## Installation
```
virtualenv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

## Setup
```
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

icsim vcan0
```

## Run
```
python3 fuzzcan.py
```

## Docs
Example program
```
conn = CanConnection(interface="vcan0")
target = Target(connection=conn,
                restart_target=False) 

session = Session(target=target,
                  sleep_time=0.01,
                  reuse_target_connection=True)

request = Request("can_frame", children=(
             Byte("data_0", 0x00),
             Byte("data_1", 0x01),
             Byte("data_2", 0x02),
             Byte("data_3", 0x03),
             Byte("data_4", 0x04, fuzzable=False),
             Byte("data_5", 0x05, fuzzable=False),
             Byte("data_6", 0x06, fuzzable=False),
             Byte("data_7", 0x07, fuzzable=False),
             ))

session.connect(request)
session.fuzz()
```
