cmake_minimum_required(VERSION 3.19)
project(crust_sworker)

set(CMAKE_CXX_STANDARD 14)
SET(SGX_SDK /opt/intel/sgxsdk)                  #SDK的安装路径
SET(SGX_MODE HW)                                #参数的设置，注意，如果给变量赋值的时候，值本身有空格，那么值需要使用“”来保证赋值的正确性，否则赋值可能存在错误
SET(SGX_ARCH x64)
SET(SGX_DEBUG 1)
SET(SGX_COMMON_CFLAGS -m64)
SET(SGX_LIBRARY_PATH ${SGX_SDK}/lib64)
SET(SGX_EDGER8R ${SGX_SDK}/bin/x64/sgx_edger8r)
SET(SGX_ENCLAVE_SIGNER ${SGX_SDK}/bin/x64/sgx_sign) #以上的参数都是根据自己的机器设置，注意不要设置错误
IF(SGX_DEBUG EQUAL 1)
    SET(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g")
ELSE(SGX_DEBUG EQUAL 1)
    SET(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2")
ENDIF(SGX_DEBUG EQUAL 1)


include_directories(src/app)
include_directories(src/app/chain)
include_directories(src/app/config)
include_directories(src/app/database)
include_directories(src/app/ecalls)
include_directories(src/app/http)
include_directories(src/app/include)
include_directories(src/app/ipfs)
include_directories(src/app/log)
include_directories(src/app/ocalls)
include_directories(src/app/process)
include_directories(src/app/utils)
include_directories(src/enclave)
include_directories(src/enclave/identity)
include_directories(src/enclave/include)
include_directories(src/enclave/persistence)
include_directories(src/enclave/report)
include_directories(src/enclave/srd)
include_directories(src/enclave/storage)
include_directories(src/enclave/utils)
include_directories(src/enclave/validator)
include_directories(src/enclave/workload)
include_directories(test/src/app)
include_directories(test/src/app/ecalls)
include_directories(test/src/app/http)
include_directories(test/src/app/ocalls)
include_directories(test/src/app/process)
include_directories(test/src/enclave/identity)
include_directories(test/src/enclave/report)
include_directories(test/src/enclave/srd)
include_directories(test/src/enclave/validator)
include_directories(test/src/enclave/workload)
include_directories(test/unit)
include_directories(test/unit/enclave)
include_directories(test/unit/enclave/storageTest)
include_directories(test/unit/enclave/utilsTest)

add_executable(crust_sworker
        src/app/chain/Chain.cpp
        src/app/chain/Chain.h
        src/app/config/Config.cpp
        src/app/config/Config.h
        src/app/database/DataBase.cpp
        src/app/database/DataBase.h
        src/app/ecalls/ECalls.cpp
        src/app/ecalls/ECalls.h
        src/app/ecalls/EnclaveQueue.cpp
        src/app/ecalls/EnclaveQueue.h
        src/app/http/ApiHandler.cpp
        src/app/http/ApiHandler.h
        src/app/http/HttpClient.cpp
        src/app/http/HttpClient.h
        src/app/http/WebServer.cpp
        src/app/http/WebServer.h
        src/app/http/WebsocketClient.cpp
        src/app/http/WebsocketClient.h
        src/app/include/Resource.h
        src/app/ipfs/Ipfs.cpp
        src/app/ipfs/Ipfs.h
        src/app/log/Log.cpp
        src/app/log/Log.h
        src/app/ocalls/IpfsOCalls.cpp
        src/app/ocalls/IpfsOCalls.h
        src/app/ocalls/OCalls.cpp
        src/app/ocalls/OCalls.h
        src/app/ocalls/PersistOCalls.cpp
        src/app/ocalls/PersistOCalls.h
        src/app/ocalls/StoreOCalls.cpp
        src/app/ocalls/StoreOCalls.h
        src/app/process/EnclaveData.cpp
        src/app/process/EnclaveData.h
        src/app/process/EntryNetwork.cpp
        src/app/process/EntryNetwork.h
        src/app/process/Process.cpp
        src/app/process/Process.h
        src/app/process/Srd.cpp
        src/app/process/Srd.h
        src/app/process/Validator.cpp
        src/app/process/Validator.h
        src/app/process/WorkReport.cpp
        src/app/process/WorkReport.h
        src/app/utils/Common.cpp
        src/app/utils/Common.h
        src/app/utils/Ctpl.h
        src/app/utils/FileUtils.cpp
        src/app/utils/FileUtils.h
        src/app/utils/FormatUtils.cpp
        src/app/utils/FormatUtils.h
        src/app/utils/SafeLock.cpp
        src/app/utils/SafeLock.h
        src/app/utils/SgxSupport.c
        src/app/utils/SgxSupport.h
        src/app/App.cpp
        src/app/App.h
        src/app/Enclave_u.c
        src/app/Enclave_u.h
        src/enclave/identity/Identity.cpp
        src/enclave/identity/Identity.h
        src/enclave/include/CrustStatus.h
        src/enclave/include/IASReport.h
        src/enclave/include/MerkleTree.h
        src/enclave/include/Parameter.h
        src/enclave/persistence/Persistence.cpp
        src/enclave/persistence/Persistence.h
        src/enclave/report/Report.cpp
        src/enclave/report/Report.h
        src/enclave/srd/Srd.cpp
        src/enclave/srd/Srd.h
        src/enclave/storage/Storage.cpp
        src/enclave/storage/Storage.h
        src/enclave/utils/Defer.h
        src/enclave/utils/EUtils.cpp
        src/enclave/utils/EUtils.h
        src/enclave/utils/Json.h
        src/enclave/utils/PathHelper.cpp
        src/enclave/utils/PathHelper.h
        src/enclave/utils/SafeLock.cpp
        src/enclave/utils/SafeLock.h
        src/enclave/validator/Validator.cpp
        src/enclave/validator/Validator.h
        src/enclave/workload/Workload.cpp
        src/enclave/workload/Workload.h
        src/enclave/Enclave.cpp
        src/enclave/Enclave.h
        src/enclave/Enclave_t.c
        src/enclave/Enclave_t.h
        test/src/app/ecalls/ECallsTest.cpp
        test/src/app/ecalls/ECallsTest.h
        test/src/app/http/ApiHandlerTest.cpp
        test/src/app/http/ApiHandlerTest.h
        test/src/app/ocalls/OCallsTest.cpp
        test/src/app/ocalls/OCallsTest.h
        test/src/app/process/AsyncTest.cpp
        test/src/app/process/AsyncTest.h
        test/src/app/process/EnclaveDataTest.cpp
        test/src/app/process/EnclaveDataTest.h
        test/src/app/process/ProcessTest.cpp
        test/src/app/process/ProcessTest.h
        test/src/app/process/SrdTest.cpp
        test/src/app/process/SrdTest.h
        test/src/app/process/ValidateTest.cpp
        test/src/app/process/ValidateTest.h
        test/src/app/AppTest.cpp
        test/src/app/AppTest.h
        test/src/enclave/identity/IdentityTest.cpp
        test/src/enclave/identity/IdentityTest.h
        test/src/enclave/report/ReportTest.cpp
        test/src/enclave/report/ReportTest.h
        test/src/enclave/srd/SrdTest.cpp
        test/src/enclave/srd/SrdTest.h
        test/src/enclave/validator/ValidatorTest.cpp
        test/src/enclave/validator/ValidatorTest.h
        test/src/enclave/workload/WorkloadTest.cpp
        test/src/enclave/workload/WorkloadTest.h
        test/src/enclave/EnclaveTest.cpp
        test/unit/enclave/storageTest/StorageTest.cpp
        test/unit/enclave/storageTest/StorageTest.h
        test/unit/enclave/utilsTest/UtilsTest.cpp
        test/unit/enclave/utilsTest/UtilsTest.h
        test/unit/enclave/EncalveTestEntrance.cpp
        test/unit/enclave/EncalveTestEntrance.h
        test/unit/MainTest.cpp
        test/unit/MainTest.h)
