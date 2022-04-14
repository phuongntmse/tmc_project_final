#!/bin/bash

sudo mos build --local --platform esp8266
sudo mos flash 
sudo mos put fs/ecc.ca.cert.pem 
sudo mos put fs/ecc.esp8266.cert.pem
sudo mos -X atca-set-key 4 slot4.key --dry-run=false
sudo mos -X atca-set-key 0 ecc.esp8266.key.pem --write-key=slot4.key --dry-run=false
sudo mos console