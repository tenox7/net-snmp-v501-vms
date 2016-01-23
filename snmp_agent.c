/*
 * Simple Network Management Protocol (RFC 1067).
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

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

#include "net-snmp-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <socket.h>
#include "vms.h"

#include "net-snmp-includes.h"
#include "snmp_lib_system.h"

#define PARSE_ERROR -1
#define BUILD_ERROR -2
#define SID_MAX_LEN 200

void	snmp_input();
void	snmp_trap();
int	create_identical();
int	parse_var_op_list();
void setVariable();

#if kinetics
char	version_descr[];
oid	version_id[];
int	version_id_len;
#endif

struct pbuf *definitelyGetBuf();
int get_community();

/* these can't be global in a multi-process router */
static u_char	_sid[SID_MAX_LEN + 1];
static int	sidlen;
u_char	*packet_end;

struct  snmp_session _session;
struct  snmp_session *session = &_session;

u_char _agentID[12] = {0};
u_long _agentBoots;
u_long _agentStartTime;
u_long _agentSize;


/* fwd: */
static int bulk_var_op_list();
static int goodValue();


#ifdef linux
#include "snmp_groupvars.h"
#endif

u_char *
snmp_auth_parse(data, length, _sid, slen, version)
    u_char	    *data;
    size_t	    *length;
    u_char	    *_sid;
    size_t	    *slen;
    long	    *version;
{
    u_char    type;

    data = asn_parse_header(data, length, &type);
    if (data == NULL){
	ERROR_MSG("bad header");
	return NULL;
    }
    if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR_MSG("wrong auth header type");
	return NULL;
    }
    data = asn_parse_int(data, length, &type, version, sizeof(*version));
    if (data == NULL){
	ERROR_MSG("bad parse of version");
	return NULL;
    }
    data = asn_parse_string(data, length, &type, _sid, slen);
    if (data == NULL){
	ERROR_MSG("bad parse of community");
	return NULL;
    }

    if( *version == SNMP_VERSION_1 ) _sid[*slen] = '\0';
    return (u_char *)data;
}

u_char *snmp_auth_build( data, length, session, is_agent, messagelen )
u_char	            *data;
size_t		    *length;
struct snmp_session *session;
int		     is_agent;
int		     messagelen;
{
	u_char *params;
	int     plen;

	params = session->community;
	plen = session->community_len;

	data = asn_build_sequence(data, length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 
	    messagelen + plen + 5);
	if (data == NULL){
		ERROR_MSG("buildheader");
		return NULL;
	}
	data = asn_build_int(data, length,
		(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		(long *)&session->version, sizeof(session->version));
	if (data == NULL){
		ERROR_MSG("buildint");
		return NULL;
	}

	data = asn_build_string(data, length,
	    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR), params, plen );
	if (data == NULL){
		ERROR_MSG("buildstring");
		return NULL;
	}

	return (u_char *)data;
}

int init_agent_auth()
{
	char hostname[ 100 ];
	struct hostent *hp;
	FILE *f;
	/* comes from snmpd.c: */
	extern char *snmp_agentinfo;

	/* agentID is based on enterprise number and local IP address */
	/* not "settable, thus, if agentBoots=0xffffffff, then all keys should be changed */
	gethostname( hostname, 100 );
	if( (hp = gethostbyname(hostname)) == NULL ) {
		return -1;
	}
	_agentID[3] = 35; /* BNR private enterprise number */
	memcpy( &_agentID[4], hp->h_addr, hp->h_length );

	if( (f = fopen( snmp_agentinfo, "r+" )) == NULL ) {
	    return -1;
	}
	fscanf( f, "%ld", &_agentBoots );
	_agentBoots++;
	fseek( f, 0, 0 );
	fprintf( f, "%ld\n", _agentBoots );
	fclose( f );


	_agentStartTime = -time(NULL);

	_agentSize = SNMP_MAX_LEN;

	return 0;
}

#ifdef KINETICS
void
snmp_input(p)
    struct pbuf *p;
{
    struct ip	    *ip = (struct ip *)p->p_off;
    int		    hlen = (int)ip->ip_hl << 2;
    register struct udp	    *udp;
    register u_char *data;  /* pointer to the rest of the unread data */
    int		    length; /* bytes of data left in msg after the "data" pointer */
    struct pbuf	    *out_packet;
    register u_char *out_data;
    int		    out_length;
    u_short	    udp_src;
    extern struct mib_udp   mib_udp;

    
    udp = (struct udp *)(p->p_off + hlen);
    if (ntohs(ip->ip_len) - hlen < sizeof(struct udp) ||    /* IP length < minimum UDP packet */
	    ntohs(udp->length) > ntohs(ip->ip_len) - hlen){ /* UDP length > IP data */
	ERROR("dropped packet with bad length");    /* delete me */
	return; /* drop packet */
    }
    data = (u_char *)udp + sizeof(struct udp);
    length = ntohs(udp->length) - sizeof(struct udp);

    out_packet = definitelyGetBuf(); /* drop packets off input queue if necessary */
    out_data = (u_char *)(out_packet->p_off + sizeof (struct ip) + sizeof (struct udp));
    out_length = MAXDATA - sizeof(struct ip) - sizeof (struct udp);

K_LEDON();
    if (!snmp_agent_parse(data, length, out_data, &out_length, (u_long)ip->ip_src)){
	K_PFREE(out_packet);
K_LEDOFF();
	return;
    }
K_LEDOFF();
    out_packet->p_len = packet_end - (u_char *)out_packet->p_off;
    setiphdr(out_packet, ip->ip_src);	/* address to source of request packet (ntohl ??? ) */
    udp_src = ntohs(udp->src);
    udp = (struct udp *)(out_packet->p_off + sizeof (struct ip));
    udp->src = htons(SNMP_PORT);
    udp->dst = htons(udp_src);
    udp->length = out_packet->p_len - sizeof(struct ip);
    udp->checksum = 0;	/* this should be computed */

    mib_udp.udpOutDatagrams++;
    routeip(out_packet, 0, 0);
}


void
snmp_trap(destAddr, trapType, specificType)
    u_long  destAddr;
    int	    trapType;
    int	    specificType;
{
    struct pbuf	    *out_packet;
    register u_char *out_data;
    register struct udp	    *udp;
    int		    out_length;
    static oid	    sysDescrOid[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
    
    out_packet = definitelyGetBuf(); /* drop packets off input queue if necessary */
    out_data = (u_char *)(out_packet->p_off + sizeof (struct ip) + sizeof (struct udp));
    out_length = MAXDATA - sizeof(struct ip) - sizeof (struct udp);

K_LEDON();
    out_packet->p_len = snmp_build_trap(out_data, out_length, version_id, version_id_len,
	conf.ipaddr, trapType, specificType, TICKS2MS(tickclock)/10, sysDescrOid, sizeof(sysDescrOid)/sizeof(oid),
	ASN_OCTET_STR, strlen(version_descr), (u_char *)version_descr);
    if (out_packet->p_len == 0){
	K_PFREE(out_packet);
K_LEDOFF();
	return;
    }
K_LEDOFF();
    out_packet->p_len += sizeof(struct ip) + sizeof(struct udp);
    setiphdr(out_packet, destAddr);	/* address to source of request packet (ntohl ??? ) */
    udp = (struct udp *)(out_packet->p_off + sizeof (struct ip));
    udp->src = htons(SNMP_PORT);
    udp->dst = htons(SNMP_TRAP_PORT);
    udp->length = out_packet->p_len - sizeof(struct ip);
    udp->checksum = 0;	/* this should be computed */

    mib_udp.udpOutDatagrams++;
    routeip(out_packet, 0, 0);
}
#endif

int
snmp_agent_parse(data, length, out_data, out_length, sourceip)
register u_char		*data;
size_t		 length;
register u_char		*out_data;
size_t		*out_length;
u_long			 sourceip;	/* possibly for authentication */
{
    u_char	    msgtype, type;
    long	    zero = 0;
    long	    reqid, errstat, errindex, dummyindex;
    register u_char *out_auth, *out_header, *out_reqid;
    u_char	    *startData = data;
    size_t    startLength = length;
    long	    version;
    u_char	   *origdata = data;
    int		    origlen = length;
    int		    ret = 0, packet_len;

    sidlen = SID_MAX_LEN;
    data = snmp_auth_parse(data, &length, _sid, &sidlen, &version);
    if (data == NULL){
	return 0;
    }
    if( version != SNMP_VERSION_1 && version != SNMP_VERSION_2c ) {
	return 0;
    }

    if( version == SNMP_VERSION_1 ) {
	    if( (ret = get_community( _sid )) != 0 ) {
		return 0;
	    }
	    session->version = SNMP_VERSION_1;
    } else {
	return 0;
    }

    data = asn_parse_header(data, &length, &msgtype);
    if (data == NULL){
	return 0;
    }

#ifdef linux
    /* XXX: increment by total number of vars at correct place: */
    snmp_intotalreqvars++;
    if (msgtype == GET_REQ_MSG)
      snmp_ingetrequests++;
    if (msgtype == GETNEXT_REQ_MSG)
      snmp_ingetnexts++;
    if (msgtype == SET_REQ_MSG)
      snmp_insetrequests++;
#endif

    if( msgtype == SNMP_MSG_GETBULK ) {
	if( session->version == SNMP_VERSION_1 ) 
		return 0;
    } else if (msgtype != SNMP_MSG_GET && msgtype != SNMP_MSG_GETNEXT && msgtype != SNMP_MSG_SET ) {
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &reqid, sizeof(reqid));
    if (data == NULL){
	ERROR_MSG("bad parse of reqid");
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &errstat, sizeof(errstat));
    if (data == NULL){
	ERROR_MSG("bad parse of errstat");
#ifdef linux
	snmp_inasnparseerrors++;
#endif
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &errindex, sizeof(errindex));
    if (data == NULL){
	ERROR_MSG("bad parse of errindex");
	return 0;
    }
    /*
     * Now start cobbling together what is known about the output packet.
     * The final lengths are not known now, so they will have to be recomputed
     * later.
     */

    out_auth = out_data;
    out_header = snmp_auth_build( out_auth, out_length, session, 1, 0 );
    if (out_header == NULL){
	ERROR_MSG("snmp_auth_build failed");
#ifdef linux
	snmp_inasnparseerrors++;
#endif
	return 0;
    }

    out_reqid = asn_build_sequence(out_header, out_length, (u_char)SNMP_MSG_RESPONSE, 0);
    if (out_reqid == NULL){
	ERROR_MSG("out_reqid == NULL");
	return 0;
    }

    type = (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    /* return identical request id */
    out_data = asn_build_int(out_reqid, out_length, type, &reqid, sizeof(reqid));
    if (out_data == NULL){
	ERROR_MSG("build reqid failed");
	return 0;
    }

    /* assume that error status will be zero */
    out_data = asn_build_int(out_data, out_length, type, &zero, sizeof(zero));
    if (out_data == NULL){
	ERROR_MSG("build errstat failed");
	return 0;
    }

    /* assume that error index will be zero */
    out_data = asn_build_int(out_data, out_length, type, &zero, sizeof(zero));
    if (out_data == NULL){
	ERROR_MSG("build errindex failed");
	return 0;
    }

    if (msgtype == SNMP_MSG_GETBULK)
	errstat = bulk_var_op_list(data, length, out_data, *out_length,
				    errstat, errindex, &errindex );
    else
	errstat = parse_var_op_list(data, length, out_data, *out_length,
			    &errindex, msgtype, RESERVE1);
    if (msgtype== SNMP_MSG_SET){
	if (errstat == SNMP_ERR_NOERROR)
	    errstat = parse_var_op_list(data, length, out_data, *out_length,
					&errindex, msgtype, RESERVE2);
        if (errstat == SNMP_ERR_NOERROR){
    	    /*
	     * SETS require 3-4 passes through the var_op_list.  The first two
	     * passes verify that all types, lengths, and values are valid
	     * and may reserve resources and the third does the set and a
	     * fourth executes any actions.  Then the identical GET RESPONSE
	     * packet is returned.
	     * If either of the first two passes returns an error, another
	     * pass is made so that any reserved resources can be freed.
	     */
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, msgtype, COMMIT);
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, msgtype, ACTION);
	      if (create_identical(startData, out_auth, startLength, 0L, 0L )){
		  *out_length = packet_end - out_auth;
		  return 1;
	      }
	      return 0;
	} else {
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, msgtype, FREE);
	}
    }
    switch((short)errstat){
	case SNMP_ERR_NOERROR:
	    /* re-encode the headers with the real lengths */
	    *out_length = packet_end - out_header;
	    packet_len = *out_length;
	    out_data = asn_build_sequence(out_header, out_length, SNMP_MSG_RESPONSE,
					packet_end - out_reqid);
	    if (out_data != out_reqid){
		ERROR_MSG("internal error: header");
		return 0;
	    }

	    *out_length = packet_end - out_auth;
	    out_data = snmp_auth_build( out_auth, out_length, session, 1, packet_end - out_header );

	    *out_length = packet_end - out_auth;
#if 0
	    /* packet_end is correct for old SNMP.  This dichotomy needs
	       to be fixed. */
	    if (session->version == SNMP_VERSION_2)
		packet_end = out_auth + packet_len;
#endif
	    break;
	case SNMP_ERR_TOOBIG:
#ifdef linux
	    snmp_intoobigs++;
#endif
#if notdone
	    if (session->version == SNMP_VERSION_2){
		create_toobig(out_auth, *out_length, reqid, pi);
		break;
	    } /* else FALLTHRU */
#endif
	case SNMP_ERR_NOACCESS:
	case SNMP_ERR_WRONGTYPE:
	case SNMP_ERR_WRONGLENGTH:
	case SNMP_ERR_WRONGENCODING:
	case SNMP_ERR_WRONGVALUE:
	case SNMP_ERR_NOCREATION:
	case SNMP_ERR_INCONSISTENTVALUE:
	case SNMP_ERR_RESOURCEUNAVAILABLE:
	case SNMP_ERR_COMMITFAILED:
	case SNMP_ERR_UNDOFAILED:
	case SNMP_ERR_AUTHORIZATIONERROR:
	case SNMP_ERR_NOTWRITABLE:
	case SNMP_ERR_NOSUCHNAME:
	case SNMP_ERR_BADVALUE:
	case SNMP_ERR_READONLY:
	case SNMP_ERR_GENERR:
	    if (create_identical(startData, out_auth, startLength, errstat,
				 errindex)){
		*out_length = packet_end - out_auth;
		return 1;
	    }
	    return 0;
	default:
	    return 0;
    }

    return 1;
}

/*
 * Parse_var_op_list goes through the list of variables and retrieves each one,
 * placing it's value in the output packet.  In the case of a set request,
 * if action is RESERVE, the value is just checked for correct type and
 * value, and resources may need to be reserved.  If the action is COMMIT,
 * the variable is set.  If the action is FREE, an error was discovered
 * somewhere in the previous RESERVE pass, so any reserved resources
 * should be FREE'd.
 * If any error occurs, an error code is returned.
 */
int
parse_var_op_list(data, length, out_data, out_length, index, msgtype, action)
    register u_char	*data;
    size_t	length;
    register u_char	*out_data;
    size_t	out_length;
    register long	*index;
    int			msgtype;
    int			action;
{
    u_char  type;
    oid	    var_name[MAX_NAME_LEN];
    size_t var_name_len, var_val_len;
    u_char  var_val_type, *var_val, statType;
    register u_char *statP;
    int	    statLen;
    u_short acl;
    int	    rw, exact, err;
    int	    (*write_method)();
    u_char  *headerP, *var_list_start;
    size_t dummyLen;
    u_char  *getStatPtr();
    int	    noSuchObject;

    if (msgtype== SNMP_MSG_SET)
	rw = WRITE;
    else
	rw = READ;
    if (msgtype == SNMP_MSG_GETNEXT){
	exact = FALSE;
    } else {
	exact = TRUE;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL){
	ERROR_MSG("not enough space for varlist");
	return PARSE_ERROR;
    }
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR_MSG("wrong type");
	return PARSE_ERROR;
    }
    headerP = out_data;
    out_data = asn_build_sequence(out_data, &out_length,
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_data == NULL){
    	ERROR_MSG("not enough space in output packet");
	return BUILD_ERROR;
    }
    var_list_start = out_data;

    *index = 1;
    while((int)length > 0){
	/* parse the name, value pair */
	var_name_len = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, var_name, &var_name_len, &var_val_type,
				 &var_val_len, &var_val, &length);
	if (data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl, 
		exact, &write_method, session->version, &noSuchObject, 
		NULL);
	if (session->version == SNMP_VERSION_1 && statP == NULL
	    && (msgtype != SNMP_MSG_SET || !write_method)){
	    ERROR_MSG("internal v1_error");
	    return SNMP_ERR_NOSUCHNAME;
	}

	/* check if this variable is read-write (in the MIB sense). */
	if( msgtype == SNMP_MSG_SET && acl != RWRITE )
	    return session->version == SNMP_VERSION_1 ? SNMP_ERR_NOSUCHNAME : SNMP_ERR_NOTWRITABLE;

	/* Its bogus to check here on getnexts - the whole packet shouldn't
	   be dumped - this should should be the loop in getStatPtr
	   luckily no objects are set unreadable.  This can still be
	   useful for sets to determine which are intrinsically writable */

	if (msgtype== SNMP_MSG_SET){
	    if (write_method == NULL){
		if (statP != NULL){
		    /* see if the type and value is consistent with this
		       entity's variable */
		    if (!goodValue(var_val_type, var_val_len, statType,
				   statLen)){
			if (session->version != SNMP_VERSION_1)
			    return SNMP_ERR_WRONGTYPE; /* poor approximation */
			else {
#ifdef linux
			    snmp_inbadvalues++;
#endif
			    return SNMP_ERR_BADVALUE;
			}
		    }
		    /* actually do the set if necessary */
		    if (action == COMMIT)
			setVariable(var_val, var_val_type, var_val_len,
				    statP, statLen);
		} else {
		    if (session->version != SNMP_VERSION_1)
			return SNMP_ERR_NOCREATION;
		    else
			return SNMP_ERR_NOSUCHNAME;
		}
	    } else {
		err = (*write_method)(action, var_val, var_val_type,
				     var_val_len, statP, var_name,
				     var_name_len);
		if (err != SNMP_ERR_NOERROR){
		    if (session->version == SNMP_VERSION_1) {
#ifdef linux
			snmp_inbadvalues++;
#endif
			return SNMP_ERR_BADVALUE;
		    } else
			return err;
		}
	    }
	} else {
	    /* retrieve the value of the variable and place it into the
	     * outgoing packet */
	    if (statP == NULL){
		statLen = 0;
		if (exact){
		    if (noSuchObject == TRUE){
			statType = SNMP_NOSUCHOBJECT;
		    } else {
			statType = SNMP_NOSUCHINSTANCE;
		    }
		} else {
		    statType = SNMP_ENDOFMIBVIEW;
		}
	    }
            out_data = snmp_build_var_op(out_data, var_name, &var_name_len,
					 statType, statLen, statP,
					 &out_length);
	    if (out_data == NULL){
	        return SNMP_ERR_TOOBIG;
	    }
	}

	(*index)++;
    }
    if (msgtype!= SNMP_MSG_SET){
	/* save a pointer to the end of the packet */
        packet_end = out_data;

        /* Now rebuild header with the actual lengths */
        dummyLen = packet_end - var_list_start;
        if (asn_build_sequence(headerP, &dummyLen,
			       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
			       dummyLen) == NULL){
	    return SNMP_ERR_TOOBIG;	/* bogus error ???? */
        }
    }
    *index = 0;
    return SNMP_ERR_NOERROR;
}

/*
 * create a packet identical to the input packet, except for the error status
 * and the error index which are set according to the input variables.
 * Returns 1 upon success and 0 upon failure.
 */
int
create_identical(snmp_in, snmp_out, snmp_length, errstat, errindex)
    u_char	    *snmp_in;
    u_char	    *snmp_out;
    int		    snmp_length;
    long	    errstat, errindex;
{
    register u_char *data;
    u_char	    type;
    u_long	    dummy;
    size_t    length, headerLength;
    register u_char *headerPtr, *reqidPtr, *errstatPtr, *errindexPtr, *varListPtr;

    bcopy((char *)snmp_in, (char *)snmp_out, snmp_length);
    length = snmp_length;
    headerPtr = snmp_auth_parse(snmp_out, &length, _sid, &sidlen, (long *)&dummy);
    _sid[sidlen] = 0;
    if (headerPtr == NULL)
	return 0;
    reqidPtr = asn_parse_header(headerPtr, &length, (u_char *)&dummy);
    if (reqidPtr == NULL)
	return 0;
    headerLength = length;
    errstatPtr = asn_parse_int(reqidPtr, &length, &type, (long *)&dummy, sizeof dummy);	/* request id */
    if (errstatPtr == NULL)
	return 0;
    errindexPtr = asn_parse_int(errstatPtr, &length, &type, (long *)&dummy, sizeof dummy);	/* error status */
    if (errindexPtr == NULL)
	return 0;
    varListPtr = asn_parse_int(errindexPtr, &length, &type, (long *)&dummy, sizeof dummy);	/* error index */
    if (varListPtr == NULL)
	return 0;

    data = asn_build_header(headerPtr, &headerLength, SNMP_MSG_RESPONSE, headerLength);
    if (data != reqidPtr)
	return 0;
    length = snmp_length;
    type = (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    data = asn_build_int(errstatPtr, &length, type, &errstat, sizeof errstat);
    if (data != errindexPtr)
	return 0;
    data = asn_build_int(errindexPtr, &length, type, &errindex, sizeof errindex);
    if (data != varListPtr)
	return 0;
    packet_end = snmp_out + snmp_length;
    return 1;
}

#ifdef KINETICS
struct pbuf *
definitelyGetBuf(){
    register struct pbuf *p;

    K_PGET(PT_DATA, p);
    while(p == 0){
#ifdef notdef
	if (pq->pq_head != NULL){
	    K_PDEQ(SPLIMP, pq, p);
	    if (p) K_PFREE(p);
	} else if (sendq->pq_head != NULL){
	    K_PDEQ(SPLIMP, sendq, p);
	    if (p) K_PFREE(p);
	}
#endif
	K_PGET(PT_DATA, p);
    }
    return p;
}
#endif


int get_community(sessionid)
u_char      *sessionid;
{
    memset( session, 0, sizeof(*session) );
    session->community = sessionid;
    session->community_len = strlen((char *)sessionid );

    return 0;
}

static int goodValue(inType, inLen, actualType, actualLen)
    u_char	inType, actualType;
    int		inLen, actualLen;
{
    if (inLen > actualLen)
	return FALSE;
    return (inType == actualType);
}


void
setVariable(var_val, var_val_type, var_val_len, statP, statLen)
    u_char  *var_val;
    u_char  var_val_type;
    int	    var_val_len;
    u_char  *statP;
    size_t statLen;
{
    size_t	    buffersize = 1000;

    switch(var_val_type){
	case ASN_INTEGER:
	case ASN_COUNTER:
	case ASN_GAUGE:
	case ASN_TIMETICKS:
	    asn_parse_int(var_val, &buffersize, &var_val_type, (long *)statP, statLen);
	    break;
	case ASN_OCTET_STR:
	case ASN_IPADDRESS:
	case ASN_OPAQUE:
	    asn_parse_string(var_val, &buffersize, &var_val_type, statP, &statLen);
	    break;
	case ASN_OBJECT_ID:
	    asn_parse_objid(var_val, &buffersize, &var_val_type, (oid *)statP, &statLen);
	    break;
    }
}

struct repeater {
    oid	name[MAX_NAME_LEN];
    size_t length;
} repeaterList[20];


static int
bulk_var_op_list(data, length, out_data, out_length, non_repeaters, max_repetitions, index)
    register u_char	*data;
    size_t	length;
    register u_char	*out_data;
    size_t	out_length;
    int			non_repeaters;
    int			max_repetitions;
    register long	*index;
{
    u_char  type;
    oid	    var_name[MAX_NAME_LEN];
    size_t var_name_len, var_val_len;
    u_char  var_val_type, *var_val, statType;
    register u_char *statP;
    size_t statLen;
    u_short acl;
    int	    (*write_method)();
    u_char  *headerP, *var_list_start;
    size_t dummyLen;
    u_char  *getStatPtr();
    u_char  *repeaterStart, *out_data_save;
    int	    repeatCount, repeaterLength, indexStart, out_length_save;
    int	    full = FALSE;
    int	    noSuchObject, useful;
    int repeaterIndex, repeaterCount;
    struct repeater *rl;

    if (non_repeaters < 0)
	non_repeaters = 0;
    max_repetitions = *index;
    if (max_repetitions < 0)
	max_repetitions = 0;

    data = asn_parse_header(data, &length, &type);
    if (data == NULL){
	ERROR_MSG("not enough space for varlist");
#ifdef linux
	snmp_inasnparseerrors++;
#endif
	return PARSE_ERROR;
    }
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR_MSG("wrong type");
#ifdef linux
	snmp_inasnparseerrors++;
#endif
	return PARSE_ERROR;
    }
    headerP = out_data;
    out_data = asn_build_sequence(out_data, &out_length,
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_data == NULL){
    	ERROR_MSG("not enough space in output packet");
	return BUILD_ERROR;
    }
    var_list_start = out_data;

    out_length -= 32;	/* slop factor */
    *index = 1;
    while((int)length > 0 && non_repeaters > 0){
	/* parse the name, value pair */
	
	var_name_len = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, var_name, &var_name_len, &var_val_type,
				 &var_val_len, &var_val, &length);
	if (data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl, 
			   FALSE, &write_method, session->version, &noSuchObject, NULL);

	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;

	/* save out_data so this varbind can be removed if it goes over
	   the limit for this packet */

	/* retrieve the value of the variable and place it into the outgoing packet */
	out_data = snmp_build_var_op(out_data, var_name, &var_name_len,
				     statType, statLen, statP,
				     &out_length);
	if (out_data == NULL){
	    return SNMP_ERR_TOOBIG;	/* ??? */
	}
	(*index)++;
	non_repeaters--;
    }

    repeaterStart = out_data;
    indexStart = *index;	/* index on input packet */

    repeaterCount = 0;
    rl = repeaterList;
    useful = FALSE;
    while((int)length > 0){
	/* parse the name, value pair */
	rl->length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, rl->name, &rl->length,
				 &var_val_type, &var_val_len, &var_val,
				 &length);
	if (data == NULL) {
#ifdef linux
	    snmp_inasnparseerrors++;
#endif
	    return PARSE_ERROR;
	}
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(rl->name, &rl->length, &statType, &statLen, 
			   &acl, FALSE, &write_method, session->version, &noSuchObject, NULL);
	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;
	else
	    useful = TRUE;

	out_data_save = out_data;
	out_length_save = out_length;
	/* retrieve the value of the variable and place it into the
	 * outgoing packet */
	out_data = snmp_build_var_op(out_data, rl->name, &rl->length,
				     statType, statLen, statP,
				     &out_length);
	if (out_data == NULL){
	    out_data = out_data_save;
	    out_length = out_length_save;
	    full = TRUE;
	}
	(*index)++;
	repeaterCount++;
	rl++;
    }
    repeaterLength = out_data - repeaterStart;
    if (!useful)
	full = TRUE;

    for(repeatCount = 1; repeatCount < max_repetitions; repeatCount++){
	data = repeaterStart;
	length = repeaterLength;
	*index = indexStart;
	repeaterStart = out_data;
	useful = FALSE;
	repeaterIndex = 0;
	rl = repeaterList;
	while((repeaterIndex++ < repeaterCount) > 0 && !full){
	    /* now attempt to retrieve the variable on the local entity */
	    statP = getStatPtr(rl->name, &rl->length, &statType, &statLen,
			 &acl, FALSE, &write_method, session->version, &noSuchObject, NULL);
	    if (statP == NULL)
		statType = SNMP_ENDOFMIBVIEW;
	    else
		useful = TRUE;

	    out_data_save = out_data;
	    out_length_save = out_length;
	    /* retrieve the value of the variable and place it into the
	     * Outgoing packet */
	    out_data = snmp_build_var_op(out_data, rl->name, &rl->length, statType, statLen, statP, &out_length);
	    if (out_data == NULL){
		out_data = out_data_save;
		out_length = out_length_save;
		full = TRUE;
		repeatCount = max_repetitions;
	    }
	    (*index)++;
	    rl++;
	}
	repeaterLength = out_data - repeaterStart;
	if (!useful)
	    full = TRUE;
    }
    packet_end = out_data;
    
    /* Now rebuild header with the actual lengths */
    dummyLen = out_data - var_list_start;
    if (asn_build_sequence(headerP, &dummyLen, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), dummyLen) == NULL){
	return SNMP_ERR_TOOBIG;	/* bogus error ???? */
    }
    *index = 0;
    return SNMP_ERR_NOERROR;
}

