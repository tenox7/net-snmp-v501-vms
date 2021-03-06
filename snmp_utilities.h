/*
 * 11.07.02 Ported to Unix
 */
#ifndef NET_SNMP_UTILITIES_H
#define NET_SNMP_UTILITIES_H

    /**
     *  Library API routines not specifically concerned with SNMP directly,
     *    but used more generally within the library, agent and other applications.
     *
     *  This also includes "standard" system routines, which are missing on
     *    particular O/S distributiones.
     */

#ifdef __vms
#include "snmp_types.h"
#else
#include <net-snmp/types.h>
#endif
    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the routines relevant to this area of the
     *  API will be identified, and listed here directly.
     *
     *  But for the time being, this header file is a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

#ifdef __vms
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_lib_getopt.h"
#else
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/getopt.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>         /* for in_addr_t */
#endif
#ifdef __vms
#include "snmp_lib_system.h"
#include "snmp_lib_tools.h"
#include "snmp_lib_asn1.h"      /* for counter64 */
#include "snmp_lib_int64.h"
#include "snmp_lib_mt_support.h"
#include "snmp_locking.h"
#include "snmp_alarm.h"
#include "snmp_lib_data_list.h"
#include "snmp_lib_oid_stash.h"
#include "snmp_lib_snmp.h"
#include "snmp_impl.h"
#include "snmp-tc.h"

#include "snmp_version.h"
#else
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/asn1.h>      /* for counter64 */
#include <net-snmp/library/int64.h>
#include <net-snmp/library/mt_support.h>
#include <net-snmp/library/snmp_locking.h>
#include <net-snmp/library/snmp_alarm.h>
#include <net-snmp/library/data_list.h>
#include <net-snmp/library/oid_stash.h>
#include <net-snmp/library/snmp.h>
#include <net-snmp/library/snmp_impl.h>
#include <net-snmp/library/snmp-tc.h>

#include <net-snmp/version.h>
#endif


#endif                          /* NET_SNMP_UTILITIES_H */
