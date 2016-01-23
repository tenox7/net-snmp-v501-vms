/*
 * 11.07.02 Ported to VMS
 */
#ifndef NET_SNMP_SESSION_API_H
#define NET_SNMP_SESSION_API_H

    /**
     *  Library API routines concerned with specifying and using SNMP "sessions"
     *    including sending and receiving requests.
     */

#ifdef _vms
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
#include "snmp_lib_callback.h"

#include "snmp_transport.h"
#include "snmpCallbackDomain.h"
#else
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/asn1.h>
#include <net-snmp/library/callback.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/snmpCallbackDomain.h>
#endif
#ifdef SNMP_TRANSPORT_UNIX_DOMAIN
#include <net-snmp/library/snmpUnixDomain.h>
#endif
#ifdef SNMP_TRANSPORT_UDP_DOMAIN
#ifdef __vms
#include "snmpUDPDomain.h"
#else
#include <net-snmp/library/snmpUDPDomain.h>
#endif
#endif
#ifdef SNMP_TRANSPORT_TCP_DOMAIN
#include <net-snmp/library/snmpTCPDomain.h>
#endif
#ifdef SNMP_TRANSPORT_UDPIPV6_DOMAIN
#include <net-snmp/library/snmpUDPIPv6Domain.h>
#endif
#ifdef SNMP_TRANSPORT_TCPIPV6_DOMAIN
#include <net-snmp/library/snmpTCPIPv6Domain.h>
#endif
#ifdef SNMP_TRANSPORT_IPX_DOMAIN
#include <net-snmp/library/snmpIPXDomain.h>
#endif
#ifdef SNMP_TRANSPORT_AAL5PVC_DOMAIN
#include <net-snmp/library/snmpAAL5PVCDomain.h>
#endif

#ifdef __vms
#include "snmp_lib_ucd_compat.h"
#else
#include <net-snmp/library/ucd_compat.h>
#endif
#endif                          /* NET_SNMP_SESSION_API_H */
