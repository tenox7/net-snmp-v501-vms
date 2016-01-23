/*
 * 16.07.02 Ported to VMS
 */
#ifdef __vms
#include "snmp_version.h"
#else
#include <net-snmp/version.h>
#endif

const char     *NetSnmpVersionInfo = "5.0.1";

const char     *
netsnmp_get_version()
{
    return NetSnmpVersionInfo;
}
