#!/bin/bash 

scp -i /home/seiga/workspace/bullseye.id_rsa -P 10022 container-escape-detector.ko root@localhost:/lib/modules/6.8.12+/kernel/extra/ 
