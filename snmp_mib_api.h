/*
 * 11.07.02 Ported to VMS
 */
#ifndef NET_SNMP_MIB_API_H
#define NET_SNMP_MIB_API_H

    /**
     *  Library API routines concerned with MIB files and objects, and OIDs
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

#include "snmp_lib_mib.h"
#include "snmp_lib_parse.h"
#include "snmp_lib_oid_array.h"
#include "snmp_lib_oid_stash.h"
#include "snmp_lib_ucd_compat.h"
#else
#include <net-snmp/library/snmp_api.h>

#include <net-snmp/library/mib.h>
#include <net-snmp/library/parse.h>
#include <net-snmp/library/oid_array.h>
#include <net-snmp/library/oid_stash.h>
#include <net-snmp/library/ucd_compat.h>
#endif
#endif                          /* NET_SNMP_MIB_API_H */
