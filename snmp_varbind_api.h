#ifndef NET_SNMP_VARBIND_API_H
#define NET_SNMP_VARBIND_API_H

    /**
     *  Library API routines concerned with variable bindings and values.
     */

#include <net-snmp/types.h>

    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the routines relevant to this area of the
     *  API will be identified, and listed here directly.
     *
     *  But for the time being, this header file is a placeholder,
     *  to allow application writers to adopt the new header file names.
     */
/*
 * 11.07.02 Ported to VMS
 */
#ifdef __vms
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_lib_mib.h"
#else
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/mib.h>
#endif
#endif                          /* NET_SNMP_VARBIND_API_H */
