#ifndef __SKBDUMP_H
#define __SKBDUMP_H

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/threads.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "dbg_option.h"

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#define MATCH 1
#define NOTMATCH 0

#define DUMP_LALL (DUMP_L2 | DUMP_L3 | DUMP_HOOK_L3 | DUMP_L4 | DUMP_L_EXPECT)

#define DUMP_LSKB (DUMP_L2 | DUMP_L3 | DUMP_HOOK_L3 | DUMP_L4)

#define MODULE_SKBDUMP_PROC "skbdump"

/* ������� */
enum VERBOSE_EN_T
{
    VERBOSE_EN_NONE = 0, /* ����ʾ���� */
    VERBOSE_EN_SKB = 1,/* ��ʾskb���� */
    VERBOSE_EN_NFCT = 1 << 1, /* ��ʾnfct���� */
    VERBOSE_EN_PROTO = 1 << 2, /* ��ʾЭ������ */
    VERBOSE_EN_EXPECT = 1 << 3, /* ��ʾ������������ */
    VERBOSE_EN_ROUTE = 1 << 4, /* ��ʾ������������ */
    VERBOSE_EN_BRIDGE = 1 << 5, /* ��ʾ������������ */

    VERBOSE_EN_MAX = 1 << 6,/* ���ֵ�����ڼ�����ϵ����ֵ */
};

/* �������� */
#define VERBOSE_EN_ALL (VERBOSE_EN_MAX - 1)

struct dump_filter_t
{
    enum dump_level_t level;
    uint32_t ip;
    uint16_t port;
    uint16_t proto;

    int32_t verbose;/* �Ƿ���ʾ��ϸ��Ϣ��Ĭ�ϲ���ʾ0 */
    atomic_t dumpstack; /* ƥ��ʱ�Ƿ��ӡ��ջ�����ڲ�ѯ���ݰ�����Դ��dump�Ĵ���Ĭ��Ϊ0 */
    int32_t expect;/* �Ƿ�������������� */
    int32_t event;/* �Ƿ����nfct�¼� */
};

extern int nfhook_init(void);
extern void nflist_cleanup(void);

static const char tcp_flag(struct tcphdr *tcph)
{
    if ( tcph->syn )
        return 'S';
    if ( tcph->rst )
        return 'R';
    if ( tcph->fin )
        return 'F';
    if ( tcph->urg )
        return 'U';
    if ( tcph->psh )
        return 'P';
    if ( tcph->ack )
        return 'A';
    return ' ';
}


static const char* get_ulong_str(ulong key)
{
#define MAX_STR_LEN     16
    static char s_str[NR_CPUS][MAX_STR_LEN];
    char *ptr = NULL;

    preempt_disable();
    ptr = s_str[smp_processor_id()];
    snprintf(ptr, MAX_STR_LEN - 1, "%lu", key);
    ptr[MAX_STR_LEN - 1] = '\0';

    preempt_enable();
    return ptr;
}

static const char *get_prot_str(int32_t protocol)
{
    switch(protocol)
    {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        break;
    }
    return get_ulong_str(protocol);
}

static const char* nfproto_str(unsigned int pf)
{
    static const char* s_pf_string[NFPROTO_NUMPROTO] =
    {
        [NFPROTO_UNSPEC...NFPROTO_NUMPROTO-1] = NULL,
        [NFPROTO_UNSPEC] = "UNSPEC",
        [NFPROTO_IPV4] = "IPV4",
        [NFPROTO_ARP] = "ARP",
        [NFPROTO_BRIDGE] = "BRIDGE",
        [NFPROTO_IPV6] = "IPV6",
        [NFPROTO_DECNET] = "DECNET",
    };

    if ( pf < NFPROTO_NUMPROTO && s_pf_string[pf] )
        return s_pf_string[pf];
    return get_ulong_str(pf);
}

static const char* hook_str(unsigned int hook)
{
    static const char* s_hook_string[NF_INET_NUMHOOKS] =
    {
        [NF_INET_PRE_ROUTING...NF_INET_NUMHOOKS-1] = NULL,
        [NF_INET_PRE_ROUTING] = "PRE",
        [NF_INET_LOCAL_IN] = "LOCALIN ",
        [NF_INET_FORWARD] = "FORWARD",
        [NF_INET_LOCAL_OUT] = "LOCALOUT",
        [NF_INET_POST_ROUTING] = "POST",
    };
    if ( hook < NF_INET_NUMHOOKS && s_hook_string[hook] )
        return s_hook_string[hook];
    return get_ulong_str(hook);
}

/* ��ȡ������ */
static const char* get_symbol(ulong addr)
{
    static char fun_name[NR_CPUS][KSYM_NAME_LEN] = {""};
    char *ptr = NULL, *pname = NULL;

    preempt_disable();
    pname = fun_name[smp_processor_id()];
    /* ��ȡ��������2�����:
    ** ���һ: ����ʧ��ʱ ��ʾ��ַ ��ʽΪ '0x��ַ'
    ** �����: �����ɹ�ʱ ��ʾ��ʽΪ '������+ƫ��/�ܴ�С ģ����'
    */
    sprint_symbol(pname, addr);
    ptr = strchr(pname, '+');
    if ( ptr )
        *ptr = '\0';

    preempt_enable();
    
    return pname;
}
#endif
