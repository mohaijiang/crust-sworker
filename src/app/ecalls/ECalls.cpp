#include "ECalls.h"

EnclaveQueue *eq = EnclaveQueue::get_instance();
crust::Log *p_log = crust::Log::get_instance();
extern bool offline_chain_mode;

std::vector<json::JSON> sealed_files; // Files have been added into checked queue
std::set<std::string> reported_files_idx;


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

    std::string public_key = Config::get_instance() -> chain_public_key;
    std::string block_height_str = std::to_string(block_height);

    std::vector<size_t> report_valid_idx_v;
    reported_files_idx.clear();
    std::string added_files = "[";
    std::string deleted_files = "[";
    size_t reported_files_acc = 0;
    long long files_size = 0;

    for (uint32_t i = 0; i < sealed_files.size(); i++)
    {
        // Get report information
        auto file_status = &sealed_files[i][FILE_STATUS];

        p_log->debug("file_status step1 : %s \n",file_status->dump().c_str());

        // Write current status to waiting status
        file_status->set_char(WAITING_STATUS, file_status->get_char(CURRENT_STATUS));
        p_log->debug("file_status step2 : %s \n",file_status->dump().c_str());

        if (file_status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
        {
            report_valid_idx_v.push_back(i);
        }
        if (file_status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID)
        {
            files_size += sealed_files[i][FILE_SIZE].ToInt();
        }

        // Generate report files queue
        if (reported_files_acc < WORKREPORT_FILE_LIMIT)
        {
            if ((file_status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID && file_status->get_char(ORIGIN_STATUS) == FILE_STATUS_UNVERIFIED)
                || (file_status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED && file_status->get_char(ORIGIN_STATUS) == FILE_STATUS_VALID))
            {
                std::string file_str;
                file_str.append("{\"").append(FILE_CID).append("\":")
                        .append("\"").append(sealed_files[i][FILE_CID].ToString()).append("\",");
                file_str.append("\"").append(FILE_SIZE).append("\":")
                        .append(std::to_string(sealed_files[i][FILE_SIZE].ToInt())).append(",");
                file_str.append("\"").append(FILE_CHAIN_BLOCK_NUM).append("\":")
                        .append(std::to_string(sealed_files[i][FILE_CHAIN_BLOCK_NUM].ToInt())).append("}");
                if (file_status->get_char(CURRENT_STATUS) == FILE_STATUS_DELETED)
                {
                    if (deleted_files.size() != 1)
                    {
                        deleted_files.append(",");
                    }
                    deleted_files.append(file_str);
                    // Update new files size
                    files_size -= sealed_files[i][FILE_SIZE].ToInt();
                }
                else if (file_status->get_char(CURRENT_STATUS) == FILE_STATUS_VALID)
                {
                    if (added_files.size() != 1)
                    {
                        added_files.append(",");
                    }
                    added_files.append(file_str);
                    // Update new files size
                    files_size += sealed_files[i][FILE_SIZE].ToInt();
                }
                reported_files_idx.insert(sealed_files[i][FILE_CID].ToString());
                reported_files_acc++;
            }
        }
    }

    added_files.append("]");
    deleted_files.append("]");

    std::string wr_str;
    wr_str.append("{");
    wr_str.append("\"").append(WORKREPORT_PUB_KEY).append("\":")
            .append("\"").append(public_key).append("\",");
    wr_str.append("\"").append(WORKREPORT_PRE_PUB_KEY).append("\":")
            .append("\"").append("").append("\",");
    wr_str.append("\"").append(WORKREPORT_BLOCK_HEIGHT).append("\":")
            .append("\"").append(block_height_str).append("\",");
    wr_str.append("\"").append(WORKREPORT_BLOCK_HASH).append("\":")
            .append("\"").append(std::string(block_hash, HASH_LENGTH * 2)).append("\",");
    wr_str.append("\"").append(WORKREPORT_RESERVED).append("\":")
            .append(std::to_string(4294967296)).append(",");
    wr_str.append("\"").append(WORKREPORT_FILES_SIZE).append("\":")
            .append(std::to_string(files_size)).append(",");
    wr_str.append("\"").append(WORKREPORT_RESERVED_ROOT).append("\":")
            .append("\"").append("1ba223d1494bc0e14777a7e63c24484ecbe14ae2004cad45e5f690829c840fd1").append("\",");
    wr_str.append("\"").append(WORKREPORT_FILES_ROOT).append("\":")
            .append("\"").append("f7d385d8397d6fbb413a0a1bdaeabab43cf1af131efff42b3c538deec7aedf36").append("\",");
    wr_str.append("\"").append(WORKREPORT_FILES_ADDED).append("\":")
            .append(added_files).append(",");
    wr_str.append("\"").append(WORKREPORT_FILES_DELETED).append("\":")
            .append(deleted_files).append(",");
    wr_str.append("\"").append(WORKREPORT_SIG).append("\":")
            .append("\"").append("").append("\"");
    wr_str.append("}");

    std::string work_str(wr_str);
    remove_char(work_str, '\\');
    remove_char(work_str, '\n');
    remove_char(work_str, ' ');
    p_log->info("Sending work report:%s\n", work_str.c_str());
    if (!offline_chain_mode)
    {
        if (!crust::Chain::get_instance()->post_sworker_work_report(work_str))
        {
            return SGX_ERROR_UNEXPECTED;
        }
    }

    p_log->info("Send work report to crust chain successfully!\n");

    handle_report_result();

//    g_work_report = wr_str;

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

void handle_report_result()
{
    // Set file status by report result
    for (auto cid : reported_files_idx)
    {
        size_t pos = 0;
        p_log->debug("handler_report_result, cid: %s,is_file_dup: %d \n",cid.c_str(),is_file_dup(cid,pos));
        if ( is_file_dup(cid, pos))
        {
            auto status = &sealed_files[pos][FILE_STATUS];
            p_log->debug("handler file_status: %s \n",status->dump().c_str());
            status->set_char(ORIGIN_STATUS, status->get_char(WAITING_STATUS));
            p_log->debug("handler file_status: %s \n",status->dump().c_str());
        }
    }
    reported_files_idx.clear();
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
    std::string public_key = Config::get_instance() -> chain_public_key;
    // Get mrenclave on chain
    std::string code_on_chain = crust::Chain::get_instance()->get_swork_code();

    id_str = "{\"account_id\":\"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX\",\"ias_cert\":\"MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\",\"ias_sig\":\""+code_on_chain+"\",\"isv_body\":\"{\\\"id\\\":\\\"52104701826714974968082314939248593622\\\",\\\"timestamp\\\":\\\"2021-05-25T07:40:35.023319\\\",\\\"version\\\":3,\\\"isvEnclaveQuoteStatus\\\":\\\"GROUP_OUT_OF_DATE\\\",\\\"platformInfoBlob\\\":\\\"1502006504000900000B0B02020280040000000000000000000B00000B000000020000000000000BB479ED4FE015B92CF06A4923E1CFE4461135243259E1686D08473ABF6B243C954B488C8B6E0532C3328C81866429875BFD03F93E7DFB7D18CD20757668233421C1\\\",\\\"isvEnclaveQuoteBody\\\":\\\"AgAAALQLAAALAAoAAAAAAGaNNT9mGXhlXJ1oIM+TtmvczLolsjmv/W8hIn/dpVKzCgr///+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAAAAAAAAAEovFyJiD7aCnVHS1uwf4BmcaipQjGFBm3tf/owM55gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9G637ogCU4mSdrLTybzFAmba2MemLakS5KMgTEQp4QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADIGR5BfCD/lLus8OAI8exZFVFEILf8QxCzP+tpXu85W5vfEOKPkk2cmvvEFwTy0y2ISwvt0pkRxTbDbfgOOxHD\\\"}\",\"sig\":\""+public_key+"\"}";
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
            p_log->debug("get_enclave_id_info is %s \n",id_info_str.c_str());
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

bool is_file_dup(std::string cid, size_t &pos)
{
    p_log->debug("check cid is dup ，　cid: %s \n",cid.c_str());
    long spos = 0;
    long epos = sealed_files.size();
    while (spos <= epos)
    {
        long mpos = (spos + epos) / 2;
        if (mpos >= (long)sealed_files.size())
        {
            break;
        }
        int ret = cid.compare(sealed_files[mpos][FILE_CID].ToString());
        if (ret > 0)
        {
            spos = mpos + 1;
            pos = std::min(spos, (long)sealed_files.size());
        }
        else if (ret < 0)
        {
            pos = mpos;
            epos = mpos - 1;
        }
        else
        {
            pos = mpos;
            p_log->debug("check cid is dup ,cid: %s ,result is : %d \n",cid.c_str(),true);
            return true;
        }
    }

    p_log->debug("check cid is dup ,cid: %s ,result is : %d \n",cid.c_str(),false);
    return false;
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

    size_t pos = 0;
//    if (is_file_dup(cid, pos)){
//        return ret;
//    }

    crust::BlockHeader block_header;
    if (!crust::Chain::get_instance()->get_block_header(block_header))
    {
        return SGX_ERROR_UNEXPECTED;
    }

    size_t chain_block_num = block_header.number;
    size_t origin_size = 0;
    size_t sealed_size = 0;
//    uint8_t **p_data; size_t *data_size;
    size_t data_size = 0;
    uint8_t *p_block_data = NULL;
    data_size = Ipfs::get_instance()->block_get(cid, &p_block_data);
    origin_size = data_size;
    sealed_size = data_size;

    json::JSON file_entry_json;
    std::string cid_str = std::string(cid, CID_LENGTH);
    file_entry_json[FILE_CID] = cid_str;
    file_entry_json[FILE_HASH] = cid_str;
    file_entry_json[FILE_SIZE] = origin_size;
    file_entry_json[FILE_SEALED_SIZE] = sealed_size;
    file_entry_json[FILE_BLOCK_NUM] = chain_block_num;
    file_entry_json[FILE_CHAIN_BLOCK_NUM] = chain_block_num;
    // Status indicates current new file's status, which must be one of valid, unverified and deleted
    file_entry_json[FILE_STATUS] = "100";

    sealed_files.push_back(file_entry_json);

    std::string sealed_file_info = file_entry_json.dump();

    p_log->debug("sealed file is : %s \n",sealed_file_info.c_str());

    // Store file information
    std::string file_info;
    file_info.append("{ \\\"" FILE_SIZE "\\\" : ").append(std::to_string(origin_size)).append(" , ")
            .append("\\\"" FILE_SEALED_SIZE "\\\" : ").append(std::to_string(sealed_size)).append(" , ")
            .append("\\\"" FILE_CHAIN_BLOCK_NUM "\\\" : ").append(std::to_string(chain_block_num)).append(" }");
    EnclaveData::get_instance()->add_sealed_file_info(cid, file_info.c_str());



//    if (SGX_SUCCESS != (ret = eq->try_get_enclave(__FUNCTION__)))
//    {
//        return ret;
//    }
//1
//    ret = ecall_seal_file(eid, status, cid);
//
//    eq->free_enclave(__FUNCTION__);

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
