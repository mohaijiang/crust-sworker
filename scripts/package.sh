#!/bin/bash
function success_exit()
{
    rm -f $SYNCFILE &>/dev/null

    # Kill alive useless sub process
    for el in ${toKillPID[@]}; do
        if ps -ef | grep -v grep | grep $el &>/dev/null; then
            kill -9 $el
        fi
    done

    rm -rf $pkgdir
}

############## MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
appdir=$instdir/src
VERSION=$(cat $instdir/VERSION)
pkgdir=$instdir/crust-tee
enclavefile="enclave.signed.so"
SYNCFILE=$instdir/.syncfile
sgxsdkdir="/opt/intel/sgxsdk"
sgxssldir="/opt/intel/sgxssl"

. $basedir/utils.sh

trap "success_exit" INT
trap "success_exit" EXIT

rm -rf $pkgdir &>/dev/null
mkdir -p $pkgdir

# Check if resource and bin directory exsited
cd $instdir
if [ ! -e "$instdir/bin" ] || [ ! -e "$instdir/resource" ]; then
    verbose INFO "Please provide the 'bin' and 'resource' required for installation"
    exit -1
fi
cd - &>/dev/null

# Generate mrenclave file
if [ x"$1" != x"debug" ]; then
    if [ ! -d "$sgxsdkdir" ] || [ ! -d "$sgxssldir" ]; then
        # Install dependencies
        bash $basedir/install_deps.sh
        if [ $? -ne 0 ]; then
            verbose ERROR "Install dependencies failed!"
            exit 1
        fi
    fi

    cd $appdir
    setTimeWait "$(verbose INFO "Building enclave.signed.so file..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make clean && make -j8 &>/dev/null
    checkRes $? "quit" "$SYNCFILE"
    cp $enclavefile $instdir/etc
    make clean
    cd - &>/dev/null
else
    cd $appdir
    make clean
    cd - &>/dev/null
fi

cd $instdir
cp -r bin etc src resource scripts $pkgdir
cp LICENSE README.md VERSION buildenv.mk $pkgdir
rm etc/$enclavefile
cd -

cd $pkgdir
rm scripts/package.sh
mv scripts/install.sh ./
cd -

cd $instdir
tar -cvf crust-tee-$VERSION.tar $(basename $pkgdir)
cd -
