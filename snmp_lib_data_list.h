/*
 * netsnmp_data_list.h
 *
 * $Id: data_list.h,v 5.0 2002/04/20 07:30:12 hardaker Exp $
 *
 * External definitions for functions and variables in netsnmp_data_list.c.
 */
/*
 * 11.07.02 Converted to VMS
 */
#ifndef DATA_LIST_H
#define DATA_LIST_H

#ifdef __cplusplus
extern          "C" {
#endif

#ifdef __vms
#include "snmp_impl.h"
#include "snmp_lib_tools.h"
#else
#include <net-snmp/library/snmp_impl.h>
#include <net-snmp/library/tools.h>
#endif
    typedef void    (Netsnmp_Free_List_Data) (void *);

    typedef struct netsnmp_data_list_s {
        struct netsnmp_data_list_s *next;
        char           *name;
        void           *data;   /* The pointer to the data passed on. */
        Netsnmp_Free_List_Data *free_func;      /* must know how to free netsnmp_data_list->data */
    } netsnmp_data_list;


    inline netsnmp_data_list *netsnmp_create_data_list(const char *,
                                                       void *,
                                                       Netsnmp_Free_List_Data
                                                       *);
    void            netsnmp_add_list_data(netsnmp_data_list **head,
                                          netsnmp_data_list *node);
    void           *netsnmp_get_list_data(netsnmp_data_list *head,
                                          const char *node);
    void            netsnmp_free_list_data(netsnmp_data_list *head);    /* single */
    void            netsnmp_free_all_list_data(netsnmp_data_list *head);        /* multiple */
    int             netsnmp_remove_list_node(netsnmp_data_list **realhead,
                                             const char *name);
    inline void    *netsnmp_get_list_node(netsnmp_data_list *head,
                                          const char *name);


#ifdef __cplusplus
}
#endif
#endif
