#!/bin/bash

basedir=$(cd `dirname $0`;pwd)
appdir=$basedir/../Miner

cd $appdir
make clean && make
if [ $? -ne 0 ]; then
    echo "[ERROR] make file failed!"
fi
echo "=================================="
echo "run app"
echo "=================================="
./app $1
cd -
