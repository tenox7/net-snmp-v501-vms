/*
 * snmptranslate.c - report or translate info about oid from mibs
 *
 * Update: 1998-07-17 <jhy@gsu.edu>
 * Added support for dumping alternate oid reports (-t and -T options).
 * Added more detailed (useful?) usage info.
 */
/************************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * 16.07.02 Ported to VMS
 */

#ifdef __vms
#include "net-snmp-config.h"
#else
#include <net-snmp/net-snmp-config.h>
#endif

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>
#ifdef __vms
#include "snmp_utilities.h"
#else
#include <net-snmp/utilities.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#ifdef __vms
#include "snmp_config_api.h"
#include "snmp_output_api.h"
#include "snmp_mib_api.h"
#else
#include <net-snmp/config_api.h>
#include <net-snmp/output_api.h>
#include <net-snmp/mib_api.h>
#endif

int             show_all_matched_objects(FILE *, const char *, oid *,
                                         size_t *, int, int);

void
usage(void)
{
    fprintf(stderr, "USAGE: snmptranslate [OPTIONS] OID [OID]...\n\n");
    fprintf(stderr, "  Version:  %s\n", netsnmp_get_version());
    fprintf(stderr, "  Web:      http://www.net-snmp.org/\n");
    fprintf(stderr,
            "  Email:    net-snmp-coders@lists.sourceforge.net\n\nOPTIONS:\n");

    fprintf(stderr, "  -h\t\t\tdisplay this help message\n");
    fprintf(stderr, "  -V\t\t\tdisplay package version number\n");
    fprintf(stderr,
            "  -m MIB[:...]\t\tload given list of MIBs (ALL loads everything)\n");
    fprintf(stderr,
            "  -M DIR[:...]\t\tlook in given list of directories for MIBs\n");
    fprintf(stderr,
            "  -D TOKEN[,...]\tturn on debugging output for the specified TOKENs\n\t\t\t   (ALL gives extremely verbose debugging output)\n");
    fprintf(stderr, "  -w WIDTH\t\tset width of tree and detail output\n");
    fprintf(stderr,
            "  -T TRANSOPTS\t\tSet various options controlling report produced:\n");
    fprintf(stderr,
            "\t\t\t  B:  print all matching objects for a regex search\n");
    fprintf(stderr, "\t\t\t  d:  print full details of the given OID\n");
    fprintf(stderr, "\t\t\t  p:  print tree format symbol table\n");
    fprintf(stderr, "\t\t\t  a:  print ASCII format symbol table\n");
    fprintf(stderr, "\t\t\t  l:  enable labeled OID report\n");
    fprintf(stderr, "\t\t\t  o:  enable OID report\n");
    fprintf(stderr, "\t\t\t  s:  enable dotted symbolic report\n");
    fprintf(stderr,
            "\t\t\t  t:  enable alternate format symbolic suffix report\n");
    fprintf(stderr,
            "  -P MIBOPTS\t\tToggle various defaults controlling mib parsing:\n");
    snmp_mib_toggle_options_usage("\t\t\t  ", stderr);
    fprintf(stderr,
            "  -O OUTOPTS\t\tToggle various defaults controlling output display:\n");
    snmp_out_toggle_options_usage("\t\t\t  ", stderr);
    fprintf(stderr,
            "  -I INOPTS\t\tToggle various defaults controlling input parsing:\n");
    snmp_in_toggle_options_usage("\t\t\t  ", stderr);
    exit(1);
}

int
main(int argc, char *argv[])
{
    int             arg;
    char           *current_name = NULL, *cp = NULL;
    oid             name[MAX_OID_LEN];
    size_t          name_length;
    int             description = 0;
    int             print = 0;
    int             find_all = 0;
    int             width = 1000000;

    /*
     * usage: snmptranslate name
     */
    while ((arg = getopt(argc, argv, "Vhm:M:w:D:P:T:O:I:")) != EOF) {
        switch (arg) {
        case 'h':
            usage();
            exit(1);

        case 'm':
            setenv("MIBS", optarg, 1);
            break;
        case 'M':
            setenv("MIBDIRS", optarg, 1);
            break;
        case 'D':
            debug_register_tokens(optarg);
            snmp_set_do_debugging(1);
            break;
        case 'V':
            fprintf(stderr, "NET-SNMP version: %s\n",
                    netsnmp_get_version());
            exit(0);
            break;
        case 'P':
            cp = snmp_mib_toggle_options(optarg);
            if (cp != NULL) {
                fprintf(stderr, "Unknown parser option to -P: %c.\n", *cp);
                usage();
                exit(1);
            }
            break;
        case 'O':
            cp = snmp_out_toggle_options(optarg);
            if (cp != NULL) {
                fprintf(stderr, "Unknown OID option to -O: %c.\n", *cp);
                usage();
                exit(1);
            }
            break;
        case 'I':
            cp = snmp_in_toggle_options(optarg);
            if (cp != NULL) {
                fprintf(stderr, "Unknown OID option to -I: %c.\n", *cp);
                usage();
                exit(1);
            }
            break;
        case 'T':
            for (cp = optarg; *cp; cp++) {
                switch (*cp) {
                case 'l':
                    print = 3;
#ifdef __vms
                    print_oid_report_en_labeledoid();
#else
                    print_oid_report_enable_labeledoid();
#endif                    break;
                case 'o':
                    print = 3;
                    print_oid_report_enable_oid();
                    break;
                case 's':
                    print = 3;
#ifdef __vms
                    print_oid_report_en_symbolic();
#else
                    print_oid_report_enable_symbolic();
#endif
                    break;
                case 't':
                    print = 3;
                    print_oid_report_enable_suffix();
                    break;
                case 'd':
                    description = 1;
                    snmp_set_save_descriptions(1);
                    break;
                case 'B':
                    find_all = 1;
                    break;
                case 'p':
                    print = 1;
                    break;
                case 'a':
                    print = 2;
                    break;
                default:
                    fprintf(stderr, "Invalid -T<lostpad> character: %c\n",
                            *cp);
                    usage();
                    exit(1);
                    break;
                }
            }
            break;
        default:
            fprintf(stderr, "invalid option: -%c\n", arg);
            usage();
            exit(1);
            break;
        }
    }

    init_snmp("snmpapp");
    if (optind < argc)
        current_name = argv[optind];

    if (current_name == NULL) {
        switch (print) {
        default:
            usage();
            exit(1);
        case 1:
            print_mib_tree(stdout, get_tree_head(), width);
            break;
        case 2:
            print_ascii_dump(stdout);
            break;
        case 3:
            print_oid_report(stdout);
            break;
        }
        exit(0);
    }

    do {
        name_length = MAX_OID_LEN;
        if (snmp_get_random_access()) {
            if (!get_node(current_name, name, &name_length)) {
                fprintf(stderr, "Unknown object identifier: %s\n",
                        current_name);
                exit(2);
            }
        } else if (find_all) {
            if (0 == show_all_matched_objects(stdout, current_name,
                                              name, &name_length,
                                              description, width)) {
                fprintf(stderr,
                        "Unable to find a matching object identifier for \"%s\"\n",
                        current_name);
                exit(1);
            }
            exit(0);
        } else if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_REGEX_ACCESS)) {
            if (0 == get_wild_node(current_name, name, &name_length)) {
                fprintf(stderr,
                        "Unable to find a matching object identifier for \"%s\"\n",
                        current_name);
                exit(1);
            }
        } else {
            if (!read_objid(current_name, name, &name_length)) {
                snmp_perror(current_name);
                exit(2);
            }
        }


        if (print == 1) {
            struct tree    *tp;
            tp = get_tree(name, name_length, get_tree_head());
            print_mib_tree(stdout, tp, width);
        } else {
            print_objid(name, name_length);
            if (description) {
                print_description(name, name_length, width);
            }
        }
        current_name = argv[++optind];
        if (current_name != NULL)
            printf("\n");
    } while (optind < argc);

    return (0);
}

/*
 * Show all object identifiers that match the pattern.
 */

int
show_all_matched_objects(FILE * fp, const char *patmatch, oid * name, size_t * name_length, int f_desc, /* non-zero if descriptions should be shown */
                         int width)
{
    int             result, count = 0;
    size_t          savlen = *name_length;
    clear_tree_flags(get_tree_head());

    while (1) {
        *name_length = savlen;
        result = get_wild_node(patmatch, name, name_length);
        if (!result)
            break;
        count++;

        fprint_objid(fp, name, *name_length);
        if (f_desc)
            fprint_description(fp, name, *name_length, width);
    }

    return (count);
}
