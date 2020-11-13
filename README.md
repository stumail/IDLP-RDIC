# Secure Light-weight Stream Data Outsourcing for Internet of Things

## Introduction
This is the demo codes for the paper "Secure Light-weight Stream Data Outsourcing for Internet of Things".

## Development
The codes are written in C++ under Debian 10, and tested under Raspbian Buster (Raspberry Pi 4), Debian 10, and Ubuntu 18.04. The dependent libraries are OpenSSL and PBC Library. Please follow these steps:

### Install g++ and make
```
$ sudo apt-get install g++ make
```

### Install OpenSSL (Development Files)
```
$ sudo apt-get install libssl-dev
```

### Install GMP Library
Download pbc-0.5.14.tar.gz from https://crypto.stanford.edu/pbc/download.html, extract all the files into a new directory and enter it, then:
```
$ sudo apt-get install libgmp-dev flex bison
$ ./configure
$ make
$ sudo make install
$ sudo ldconfig
```

### Compile

#### PMN
Copy PMN.cpp and a.param to a directory and enter it, then:
```
$ g++ PMN.cpp -o PMN -lcrypto -lgmp -lpbc
```

#### RS
Copy RS.cpp to a directory and enter it, then:
```
$ g++ RS.cpp -o RS -lcrypto -lgmp -lpbc
```

#### Designated Verifier
Copy Designated-Verifier.cpp to a directory and enter it, then:
```
$ g++ Designated-Verifier.cpp -o Designated-Verifier -lcrypto -lgmp -lpbc
```

#### Witness Verifiers
For each witness verifier, copy Witness-Verifier.cpp to a directory and enter it, then:
```
$ g++ Witness-Verifier.cpp -o Witness-Verifier -lcrypto -lgmp -lpbc
```

#### Node
Copy Node.cpp to a directory and enter it, then:
```
$ g++ Node.cpp -o Node -lcrypto -lgmp -lpbc
```

## Run

### Run PMN
```
$ ./PMN 6000 65536
```
Please replace 6000 to the actual port of the PMN, replace 65536 to the actual sector number for each block.

### Run RS
```
$ ./RS 192.168.0.1 6000 6100
```
Please replace 192.168.0.1 and 6000 to the actual IP and port of the PMN, replace 6100 to the actual port of the RS.

### Run Designated Verifier
```
$ ./Designated-Verifier 192.168.0.1 6000 7000
```
Please replace 192.168.0.1 and 6000 to the actual IP and port of the PMN, replace 7000 to the actual port of the designated verifier.

### Run Witness Verifiers
```
$ ./Witness-Verifier 192.168.0.1 6000 7100
```
Please replace 192.168.0.1 and 6000 to the actual IP and port of the PMN, replace 7100 to the actual port of the witness verifier. You can run several witness verifiers simultaneously, but please ensure that the IPs and ports do not conflict.

### Run Node
```
$ ./Node 192.168.0.1 6000 6200 nid fid 1024
```
Please replace 192.168.0.1 and 6000 to the actual IP and port of the PMN, replace 6200 to the actual port of the node, replace "nid" to the actual ID of the node, replace "fid" to the actual ID of the file, replace 1024 to the actual block number of the file. (For a sector size 65536, a file in 1024 blocks is 1024*65536*16 Byte, i.e., 1 GB.)
