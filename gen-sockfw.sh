#!/bin/bash -x

PATH=$PATH:./target/debug

B=simplecae

$B key gen ./build/sockfw-ca.pem
$B ca -N "sockfw-test" ./build/sockfw-ca.pem ./build/sockfw-ca.crt

$B key gen ./build/sockfw-serv.pem
$B key pub ./build/sockfw-serv.pem ./build/sockfw-serv.pub.pem
$B csr -N "sockfw-server" --ext-server ./build/sockfw-ca.crt  ./build/sockfw-serv.pem  ./build/sockfw-serv.csr
$B sign ./build/sockfw-ca.crt ./build/sockfw-ca.pem ./build/sockfw-serv.pub.pem ./build/sockfw-serv.csr ./build/sockfw-serv.crt

$B key gen ./build/sockfw-client.pem
$B key pub ./build/sockfw-client.pem ./build/sockfw-client.pub.pem
$B csr -N "sockfw-client" --ext-server --san-dns "*.example.com" ./build/sockfw-ca.crt ./build/sockfw-client.pem  ./build/sockfw-client.csr
$B sign ./build/sockfw-ca.crt ./build/sockfw-ca.pem ./build/sockfw-client.pub.pem ./build/sockfw-client.csr ./build/sockfw-client.crt

openssl x509  -text -in ./build/sockfw-ca.crt
openssl x509  -text -in ./build/sockfw-serv.crt
openssl x509  -text -in ./build/sockfw-client.crt
