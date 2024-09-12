#!/bin/bash 

# scp -i /home/seiga/workspace/bullseye.id_rsa -P 10022 container-escape-detector.ko root@localhost:/lib/modules/7.8.12+/kernel/extra/ 
scp -i /home/seiga/workspace/bullseye.id_rsa -P 10022 *.ko root@localhost:~/ 
