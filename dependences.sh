#!/bin/sh

# sudo apt-get install libssl-dev libsqlite3-dev libsodium-dev libargon2-dev cmake make gcc -y

if [ ! -e build ];then
	mkdir build
fi

cd build
export CC=`which gcc`
cmake ..
make install
