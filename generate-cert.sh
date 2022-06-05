#!/bin/bash


mkdir -p ./cert
echo "Trying to generate self signed public and private keys"
openssl req -x509 -days 365 -nodes -newkey rsa:2048 -keyout ./cert/self.key -out ./cert/self.crt
echo "keys generated successfully"