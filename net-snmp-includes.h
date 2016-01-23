/*
 * 11.07.02 Ported to VMS
 */

#ifndef NET_SNMP_INCLUDES_H
#define NET_SNMP_INCLUDES_H

#ifdef __vms
#pragma environment save
#pragma environment header_defaults
#endif

    /**
     *  Convenience header file to pull in the full
     *     Net-SNMP library API in one go, together with
     *     certain commonly-required system header files.
     */


    /*
     *  Common system header requirements
     */
#include <stdio.h>
#include <sys/types.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/*
 * Must be right after system headers, but before library code for best usage 
 */
#ifdef HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

  /*
   * The check for missing 'in_addr_t' is handled
   * within the main net-snmp-config.h file 
   */


    /*
     *  The full Net-SNMP API
     */
#ifdef __vms
#include "snmp_definitions.h"
#include "snmp_types.h"

#include "snmp_utilities.h"
#include "snmp_session_api.h"
#include "snmp_pdu_api.h"
#include "snmp_mib_api.h"
#include "snmp_varbind_api.h"
#include "snmp_config_api.h"
#include "snmp_output_api.h"
#include "snmp_utilities.h"
#include "snmpv3_api.h"
#else
#include <net-snmp/definitions.h>
#include <net-snmp/types.h>

#include <net-snmp/utilities.h>
#include <net-snmp/session_api.h>
#include <net-snmp/pdu_api.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/varbind_api.h>
#include <net-snmp/config_api.h>
#include <net-snmp/output_api.h>
#include <net-snmp/utilities.h>
#include <net-snmp/snmpv3_api.h>
#endif

#ifdef CMU_COMPATIBLE
#include <net-snmp/library/cmu_compat.h>
#endif

#ifdef __vms
#pragma environment restore
#endif

#endif                          /* NET_SNMP_INCLUDES_H */
