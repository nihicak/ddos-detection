# ddos-detection

Requirement
- python 3.10+

## Set up
Install UFW
```
sudo apt-get install ufw
```

Install PM2
```
sudo apt-get install jq npm && sudo npm install -g pm2
```

Install pip packages
```
pip install scapy
pip install requests
```

## Usage
```
pm2 start ddos_detect.py --name ddos_protection --interpreter python3
```
