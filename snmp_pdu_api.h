/*
 * 11.07.02 Port to VMS
 */

#ifndef NET_SNMP_PDU_API_H
#define NET_SNMP_PDU_API_H

    /**
     *  Library API routines concerned with SNMP PDUs.
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
#include "snmp_lib_asn1.h"
#else
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/asn1.h>
#endif
#endif                          /* NET_SNMP_PDU_API_H */
