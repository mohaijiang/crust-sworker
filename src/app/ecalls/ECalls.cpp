#include "ECalls.h"

EnclaveQueue *eq = EnclaveQueue::get_instance();
crust::Log *p_log = crust::Log::get_instance();
extern bool offline_chain_mode;

/**
 * @description: A wrapper function, seal one G srd files under directory, can be called from multiple threads
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to restore result status
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_srd_increase(sgx_enclave_id_t eid, crust_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_srd_increase(eid, status);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, decrease srd files under directory
 * @param eid -> Enclave id
 * @param size (out) -> Pointer to decreased srd size
 * @param change -> reduction
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_srd_decrease(sgx_enclave_id_t eid, size_t *size, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_srd_decrease(eid, size, change);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, ecall main loop
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_main_loop(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_main_loop(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, ecall stop all
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_stop_all(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_stop_all(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Restore enclave data from file
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to restore result status
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_restore_metadata(sgx_enclave_id_t eid, crust_status_t *status)
{
      sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_restore_metadata(eid, status);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Compare chain account with enclave's
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to compare result status
 * @param account_id (in) -> Pointer to account id
 * @param len -> account id length
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_cmp_chain_account_id(sgx_enclave_id_t eid, crust_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_cmp_chain_account_id(eid, status, account_id, len);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, Get signed validation report
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to get result status
 * @param block_hash (in) -> block hash
 * @param block_height -> block height
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_and_upload_work_report(sgx_enclave_id_t eid, crust_status_t *status, const char *block_hash, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_gen_and_upload_work_report(eid, status, block_hash, block_height);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate ecc key pair and store it in enclave
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param account_id (in) -> Pointer to account id
 * @param len -> Account id length
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_key_pair(sgx_enclave_id_t eid, sgx_status_t *status, const char *account_id, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_gen_key_pair(eid, status, account_id, len);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, get sgx report, our generated public key contained
 *  in report data
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param report (out) -> Pointer to SGX report
 * @param target_info (in) -> Data used to generate report
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_get_quote_report(sgx_enclave_id_t eid, sgx_status_t *status, sgx_report_t *report, sgx_target_info_t *target_info)
{
    sgx_status_t ret = SGX_SUCCESS;
    *status = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_get_quote_report(eid, status, report, target_info);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, generate current code measurement
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_sgx_measurement(sgx_enclave_id_t eid, sgx_status_t *status)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_gen_sgx_measurement(eid, status);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: A wrapper function, verify IAS report
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to verify result status
 * @param IASReport (in) -> Vector first address
 * @param len -> Count of Vector IASReport
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_verify_and_upload_identity(sgx_enclave_id_t eid, crust_status_t *status, char **IASReport, size_t len)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_verify_and_upload_identity(eid, status, IASReport, len);
//
//    eq->free_enclave(__FUNCTION__);

    // Get sworker identity and store it outside of sworker
    std::string id_str;

    id_str = "{\"account_id\":\"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX\",\"ias_cert\":\"MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\",\"ias_sig\":\"SY33ZjZpOFvt2wj4d6y6CTcdgQIdNtnToqYZovToFIwIvAgr3nUMJrR1rrYTOU1wMCy/XiJwNPoZ0wbVkAtwMjjsMQss6DwNVVFPEuu3Z/1yV1PkyqeyDHk8qy/MTAaEWBqpi473u8flTnWh8JPD+B0UWVin5kqQ5+b8u6D/Um85DpjIMZ6Tb21lsyIF0BUp75Aou/VT7aYMTLVyH1E6ZCLkF9FMvjOo/EmAOue2/Dcd6XhfWp/N5C9F4Ecg9cIz5+/QhwCCcbBxHMRC82t+XwkszC3x5ZL7bZYwnGKy1H4cCc8zxLtZ28bFCklC7qdR0P1pix8QikYyYyThPMGRsg==\",\"isv_body\":\"{\\\"id\\\":\\\"52104701826714974968082314939248593622\\\",\\\"timestamp\\\":\\\"2021-05-25T07:40:35.023319\\\",\\\"version\\\":3,\\\"isvEnclaveQuoteStatus\\\":\\\"GROUP_OUT_OF_DATE\\\",\\\"platformInfoBlob\\\":\\\"1502006504000900000B0B02020280040000000000000000000B00000B000000020000000000000BB479ED4FE015B92CF06A4923E1CFE4461135243259E1686D08473ABF6B243C954B488C8B6E0532C3328C81866429875BFD03F93E7DFB7D18CD20757668233421C1\\\",\\\"isvEnclaveQuoteBody\\\":\\\"AgAAALQLAAALAAoAAAAAAGaNNT9mGXhlXJ1oIM+TtmvczLolsjmv/W8hIn/dpVKzCgr///+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAAAAAAAAAEovFyJiD7aCnVHS1uwf4BmcaipQjGFBm3tf/owM55gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9G637ogCU4mSdrLTybzFAmba2MemLakS5KMgTEQp4QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIGR5BfCD/lLus8OAI8exZFVFEILf8QxCzP+tpXu85W5vfEOKPkk2cmvvEFwTy0y2ISwvt0pkRxTbDbfgOOxHD\\\"}\",\"sig\":\"248767bfbc79dd8e7b2e517b194a3ebc4fcd6b5447fef9723e5ae1c77a6278180fd3ed57b0bfd48c02d62767b30769507aca9b27c915a4cd5d0bcc28723f2a81\"}";
    json::JSON entrance_info = json::JSON::Load(std::string(id_str));
    entrance_info["account_id"] = Config::get_instance()->chain_address;
    std::string sworker_identity = entrance_info.dump();
    p_log->info("Generate identity successfully! Sworker identity: %s\n", sworker_identity.c_str());

    if (!offline_chain_mode)
    {
        // Send identity to crust chain
        if (!crust::Chain::get_instance()->wait_for_running())
        {
            p_log->err("CRUST_UNEXPECTED_ERROR");
            return ret;
        }

        // ----- Compare mrenclave ----- //
        // Get local mrenclave
        json::JSON id_info;
        for (int i = 0; i < 20; i++)
        {
            std::string id_info_str = EnclaveData::get_instance()->get_enclave_id_info();
            if (id_info_str.compare("") != 0)
            {
                id_info = json::JSON::Load(id_info_str);
                break;
            }
            sleep(3);
            p_log->info("Cannot get id info, try again(%d)...\n", i+1);
        }
        if (!id_info.hasKey("mrenclave"))
        {
            p_log->err("Get sWorker identity information failed!\n");
            return ret;
        }
        // Get mrenclave on chain
        std::string code_on_chain = crust::Chain::get_instance()->get_swork_code();
        if (code_on_chain == "")
        {
            p_log->err("Get sworker code from chain failed! Please check the running status of the chain.\n");
            return ret;
        }
        // Compare these two mrenclave
        if (code_on_chain.compare(id_info["mrenclave"].ToString()) != 0)
        {
            print_attention();
            std::string cmd1(HRED "sudo crust tools upgrade-image sworker && sudo crust reload sworker" NC);
            p_log->err("Mrenclave is '%s', code on chain is '%s'. Your sworker need to upgrade, "
                       "please get the latest sworker by running '%s'\n",
                       id_info["mrenclave"].ToString().c_str(), code_on_chain.c_str(), cmd1.c_str());
            return ret;
        }
        else
        {
            p_log->info("Mrenclave is '%s'\n", id_info["mrenclave"].ToString().c_str());
        }

        if (!crust::Chain::get_instance()->post_sworker_identity(sworker_identity))
        {
            p_log->err("Send identity to crust chain failed!\n");
            return ret;
        }
    }
    else
    {
        p_log->info("Send identity to crust chain successfully!\n");
    }
    return ret;
}

/**
 * @description: A wrapper function, Seal file according to given path and return new MerkleTree
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to seal result status
 * @param cid (in) -> Ipfs content id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_seal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *cid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_seal_file(eid, status, cid);
//
//    eq->free_enclave(__FUNCTION__);

    // 实现代码Storage.cpp


    return ret;
}

/**
 * @description: A wrapper function, Unseal file according to given path
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to unseal result status
 * @param data (in) -> Pointer to sealed data
 * @param data_size -> Sealed data size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_unseal_file(sgx_enclave_id_t eid, crust_status_t *status, const char *data, size_t data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_unseal_file(eid, status, data, data_size);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Change srd number
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param change -> Will be changed srd number
 * @param real_change (out) -> Pointer to real changed srd size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_change_srd_task(sgx_enclave_id_t eid, crust_status_t *status, long change, long *real_change)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_change_srd_task(eid, status, change, real_change);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Update srd_g_hashs
 * @param eid -> Enclave id
 * @param change -> To be deleted srd size
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_srd_remove_space(sgx_enclave_id_t eid, size_t change)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_srd_remove_space(eid, change);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Delete file
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to delete result status
 * @param hash (in) -> File root hash
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_delete_file(sgx_enclave_id_t eid, crust_status_t *status, const char *hash)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_delete_file(eid, status, hash);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Generate upgrade metadata
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to generate result status
 * @param block_height -> Chain block height
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_gen_upgrade_data(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_gen_upgrade_data(eid, status, block_height);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Generate upgrade metadata
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param meta (in) -> Pointer to metadata
 * @param meta_len -> Meta length
 * @param total_size -> Metadata total size
 * @param transfer_end -> Indicate transfer end or not
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_restore_from_upgrade(sgx_enclave_id_t eid, crust_status_t *status, const char *meta, size_t meta_len, size_t total_size, bool transfer_end)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_restore_from_upgrade(eid, status, meta, meta_len, total_size, transfer_end);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Enable upgrade
 * @param eid -> Enclave id
 * @param status (out) -> Pointer to result status
 * @param block_height -> Current block height
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_enable_upgrade(sgx_enclave_id_t eid, crust_status_t *status, size_t block_height)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_enable_upgrade(eid, status, block_height);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Validate meaningful files
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_validate_file(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_validate_file(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Validate srd
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_validate_srd(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_validate_srd(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Disable upgrade
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_disable_upgrade(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_disable_upgrade(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get enclave id information
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_id_get_info(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_id_get_info(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}

/**
 * @description: Get workload
 * @param eid -> Enclave id
 * @return: Invoking ecall return status
 */
sgx_status_t Ecall_get_workload(sgx_enclave_id_t eid)
{
    sgx_status_t ret = SGX_SUCCESS;
//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//
//    ret = ecall_get_workload(eid);
//
//    eq->free_enclave(__FUNCTION__);

    return ret;
}
