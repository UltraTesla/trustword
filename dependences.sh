sudo apt-get install libssl-dev libsqlite3-dev libsodium-dev libargon2-dev cmake make gcc -y
mkdir build && cd build
export CC=`which gcc`
cmake ..
sudo make install
