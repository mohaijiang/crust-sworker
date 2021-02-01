#ifndef _APP_SRD_H_
#define _APP_SRD_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <string>
#include <vector>
#include <unordered_set>

#include "Config.h"
#include "FileUtils.h"
#include "FormatUtils.h"
#include "DataBase.h"
#include "Log.h"
#include "EnclaveData.h"
#include "Ctpl.h"
#include "HttpClient.h"

// Indicates default srd ratio
#define SRD_RATIO_DEFAULT 0.7
// Srd ratio upper limit
#define SRD_RATIO_UPPER 0.95
// Indicates srd upgrade timeout
#define SRD_UPGRADE_TIMEOUT 20

#define SRD_UPGRADE_INFO "srd_upgrade_info"
#define SRD_UPGRADE_INFO_TIMEOUT "timeout"
#define SRD_UPGRADE_INFO_SRD "srd"


#if defined(__cplusplus)
extern "C"
{
#endif

json::JSON get_increase_srd_info();
crust_status_t srd_change(long change);
void srd_check_reserved(void);
size_t get_reserved_space();
void set_running_srd_task(long srd_task);
long get_running_srd_task();
void decrease_running_srd_task();

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_SRD_H_*/
