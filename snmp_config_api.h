#ifndef NET_SNMP_CONFIG_API_H
#define NET_SNMP_CONFIG_API_H

    /**
     *  Library API routines concerned with configuration and control
     *    of the behaviour of the library, agent and other applications.
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
 * 11.07.02 Ported to VAX
 */
#ifdef __vms
#include "snmp_api.h"

#include "snmp_lib_read_config.h"
#include "snmp_lib_default_store.h"
#else
#include <net-snmp/library/snmp_api.h>

#include <net-snmp/library/read_config.h>
#include <net-snmp/library/default_store.h>
#endif
#include <stdio.h>              /* for FILE definition */

#ifdef __vms
#include "snmp_parse_args.h"
#include "snmp_enum.h"
#include "snmp_lib_vacm.h"
#else
#include <net-snmp/library/snmp_parse_args.h>
#include <net-snmp/library/snmp_enum.h>
#include <net-snmp/library/vacm.h>
#endif
#endif                          /* NET_SNMP_CONFIG_API_H */
