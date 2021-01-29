#!/bin/sh

BUILD_FOLDER="build"

# sudo apt-get install libssl-dev libsqlite3-dev libsodium-dev libargon2-dev cmake make gcc -y

if [ ! -e "$BUILD_FOLDER" ];then
	mkdir "$BUILD_FOLDER"

fi

cd "$BUILD_FOLDER"
export CC=`which gcc`
cmake ..
sudo make install
