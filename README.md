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
