# ddos-detection

Requirement
- python 3.10+

## Set up
```
pip install scapy
pip install requests
```

Install pm2
```
sudo apt-get install jq npm && sudo npm install -g pm2
```

## Usage
```
pm2 start ddos_detect.py --name ddos_protection --interpreter python3
```
