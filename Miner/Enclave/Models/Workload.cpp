#include "Workload.h"

Workload *workload = new Workload();

/**
 * @description: get the global workload
 * @return: the global workload
 */
Workload *get_workload()
{
    return workload;
}

/**
 * @description: constructor
 */
Workload::Workload()
{
    this->empty_disk_capacity = 0;
    for (size_t i = 0; i < 32; i++)
    {
        this->empty_root_hash[i] = 0;
    }
}

/**
 * @description: destructor
 */
Workload::~Workload()
{
    for (size_t i = 0; i < this->empty_g_hashs.size(); i++)
    {
        delete[] this->empty_g_hashs[i];
    }

    this->empty_g_hashs.clear();
}

/**
 * @description: print work report
 */
void Workload::show(void)
{
    eprintf("Empty root hash: \n");
    for (size_t i = 0; i < 32; i++)
    {
        eprintf("%02x", this->empty_root_hash[i]);
    }
    eprintf("\n");
    eprintf("Empty capacity: %luG\n", this->empty_disk_capacity);

    eprintf("Meaningful work is: \n");
    for (auto it = this->files.begin(); it != this->files.end(); it++)
    {
        eprintf("Hash->%s, Size->%luB\n", unsigned_char_array_to_hex_char_array(it->first.data(), PLOT_HASH_LENGTH), it->second);
    }
}

/**
 * @description: use block hash to serialize work report
 * @param block_hash -> use this hash to create report
 * @return: the work report
 */
std::string Workload::serialize(const char *block_hash)
{
    this->report = "{";
    this->report += "'block_hash':'" + std::string(block_hash) + "',";
    this->report += "'empty_root_hash':'" + unsigned_char_array_to_hex_string(this->empty_root_hash, PLOT_HASH_LENGTH) + "',";
    this->report += "'empty_disk_capacity':" + std::to_string(this->empty_disk_capacity) + ",";
    this->report += "files:[";
    for (auto it = this->files.begin(); it != this->files.end(); it++)
    {
        report += "{'hash':'" + unsigned_char_array_to_hex_string(it->first.data(), PLOT_HASH_LENGTH) + "','size':" + std::to_string(it->second) + "},";
    }
    this->report += "]}";

    return this->report;
}
