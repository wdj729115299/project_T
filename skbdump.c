#include "skbdump.h"

static struct dump_filter_t s_filter;
static atomic_t s_dump_enable = ATOMIC_INIT(0);

static struct nf_conn* find_get_nfct(uint32_t saddr, uint32_t daddr
                                     , ushort sport, ushort dport, ushort prot)
{
    struct nf_conn *ct = NULL;
    struct nf_conntrack_tuple_hash *hct = NULL;
    struct nf_conntrack_tuple tuple, invtuple;

    memset(&tuple, 0, sizeof(tuple));
    tuple.src.l3num = PF_INET;
    tuple.src.u.all = sport;
    tuple.src.u3.ip = saddr;
    tuple.dst.u3.ip = daddr;
    tuple.dst.u.all = dport;
    tuple.dst.protonum = prot;

    hct = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
    if ( NULL == hct )
    {
        nf_ct_invert_tuplepr(&invtuple, &tuple);
        hct = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &invtuple);
    }
    if ( hct )
        ct = nf_ct_tuplehash_to_ctrack(hct);
    return ct;
}

static const char* get_nfct_tcp_state(u_int8_t state)
{
    static const char *const s_tcp_state[] =
    {
        "NONE",
        "SYN_SENT",
        "SYN_RECV",
        "ESTABLISHED",
        "FIN_WAIT",
        "CLOSE_WAIT",
        "LAST_ACK",
        "TIME_WAIT",
        "CLOSE",
        "SYN_SENT2",
    };
    if ( state >= ARRAY_SIZE(s_tcp_state) )
        return get_ulong_str(state);
    return s_tcp_state[state];
}
static void dump_nfct_proto(union nf_conntrack_proto *proto, ushort prot)
{
    if ( IPPROTO_TCP == prot )
    {
        struct ip_ct_tcp *tcps = &proto->tcp;
        printk(" %s last_dir=%u retrans=%u last_index=%u last_seq=%u"
               " last_ack=%u last_end=%u last_win=%u last_wscale=%u"
               " last_flags=%u"
               , get_nfct_tcp_state(tcps->state)
               , tcps->last_dir, tcps->retrans, tcps->last_index
               , tcps->last_seq, tcps->last_ack, tcps->last_end
               , tcps->last_win, tcps->last_wscale
               , tcps->last_flags
              );
    }
}
static void dbg_nfct_detail(struct nf_conn *ct)
{
    //printk(NFCT_FMT, NFCT_ARG(ct));

    spin_lock_bh(&ct->lock);
    dump_nfct_proto(&ct->proto
                    , ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum);
    spin_unlock_bh(&ct->lock);
	/*
    printk(" fluxlog{flag:%u gw:%u type:%u}\n"
                , nf_ct_ext_ac(ct)->flux_flag
                , nf_ct_ext_ac(ct)->is_gw_ct
                , nf_ct_ext_wcc(ct)->conn_type
                );
    */
}

static  int32_t dbg_nfct(const char *buf, int32_t count
                         , int32_t start, void *opt)
{
    uint saddr = 0, daddr = 0;
    ushort sport = 0, dport = 0;
    ushort prot = 0;
    int dbg = 0;
    struct nf_conn *ct = NULL;
    struct dbg_option_t dbg_opt[] =
    {
        {"prot", dbg_parse_prot, &prot},
        {"saddr", dbg_parse_ipv4, &saddr},
        {"daddr", dbg_parse_ipv4, &daddr},
        {"sport", dbg_parse_port, &sport},
        {"dport", dbg_parse_port, &dport},
    };

    start = dbg_get_option(dbg_opt, ARRAY_SIZE(dbg_opt), buf, count);
    ct = find_get_nfct(saddr, daddr, sport, dport, prot);
    if ( NULL == ct )
    {
        printk("Not found nfct %s %pI4:%u->%pI4:%u\n"
               , get_prot_str(prot)
               , &saddr, ntohs(sport)
               , &daddr, ntohs(dport));
        return start;
    }

    dbg_nfct_detail(ct);
    nf_ct_put(ct);
    return start;
}

/* 匹配cttuple 1 match; 0 not match
** param part 是否模糊匹配，part 1 进行模糊匹配；0 精确匹配*/
static int match_nf_ct_tuple(const struct nf_conntrack_tuple *tuple
                             , const struct dump_filter_t *filter
                             , int part)
{
    if ( tuple->src.u3.ip == filter->ip )
    {
        if ( tuple->src.u.tcp.port == filter->port || part )
            return MATCH;
    }
    if ( tuple->dst.u3.ip == filter->ip )
    {
        if ( tuple->dst.u.tcp.port == filter->port || part)
            return MATCH;
    }
    return NOTMATCH;
}


/* 匹配nf_conn ; 1 match; 0 not match
** 支持模糊匹配 part 为1 即为模糊匹配
*/
static int match_nfct(const struct nf_conn *ct, int part)
{
    const struct nf_conntrack_tuple *st = NULL, *dt = NULL;

    if ( NULL == ct )
        return NOTMATCH;

    st = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    dt = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;

    if(MATCH == match_nf_ct_tuple(st, &s_filter, part)
            || MATCH == match_nf_ct_tuple(dt, &s_filter, part))
    {
        return MATCH;
    }

    return NOTMATCH;
}

/*  匹配nfct 如果当前ct不匹配，则会向上一匹配master 直到匹配为止
** 这个函数不支持模糊匹配
*/
static int match_nfct_master(const struct nf_conn *ct)
{
    const struct nf_conn *master = ct;

    if ( NULL == ct )
        return NOTMATCH;

    if ( MATCH == match_nfct(ct, 0) )
        return MATCH;

    if ( !s_filter.expect )
        return NOTMATCH;

    master = ct->master;
    while ( master )
    {
        if ( MATCH == match_nfct(master, 0) )
            return MATCH;
        master = master->master;
    }
    return NOTMATCH;
}


/* 匹配skb ; 1 match; 0 not match */
static int match_skb(const struct sk_buff *skb)
{
    const struct iphdr *iph = NULL;
    const struct nf_conn *ct = NULL, *master = NULL;
    enum ip_conntrack_info ctinfo;
    const struct nf_conntrack_tuple *st = NULL;

    ct = nf_ct_get(skb, &ctinfo);
    if ( NULL == ct )
        return NOTMATCH;
    st = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    if ( st->dst.protonum != s_filter.proto )
    {
        master = ct->master;
        if ( master )
        {
            st = &master->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
        }

        if ( st->dst.protonum != s_filter.proto )
            return NOTMATCH;
    }

    iph = ip_hdr(skb);
    if ( unlikely(NULL == iph) )
        return NOTMATCH;
    switch(s_filter.proto)
    {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        if(MATCH == match_nfct(ct, 0))
        {
            return MATCH;
        }
        else if ( s_filter.expect && IP_CT_RELATED == ctinfo )
        {
            /* 只要子连接匹配上了expect，则处于IP_CT_RELEATED状态，
            ** 直到收到回复方向上的包，其状态才会改变
            ** TCP协议接收synack时就会改变；UDP协议需要接收回复的包才能改变
            ** 所以这里可能会多次进来，NAT场景下视频 h323的部分udp连接只有单向包
            */
            if ( MATCH == match_nfct_master(ct->master) )
                return MATCH;
        }
        break;
    case IPPROTO_ICMP:
        if ( iph->saddr == s_filter.ip || iph->daddr == s_filter.ip )
        {
            return MATCH;
        }
        break;
    default:
        break;
    }
    return NOTMATCH;

}

/*******************************************************************************
**   参    数:   [in]   ...钩子标准参数
**   功能描述:   这个钩子位于nf_conntrack之后，主要是为了匹配skb之用的，
                 放在nf_conntrack则可以匹配原始方向与回复方向不同时
**   返 回 值:
**   注    意:   不要在这个钩子中增加信息输出，真正的信息输出应该在dump_skb中添加
**   历史记录:
             1.  2013-11-15 create by wangzheng24937.
*******************************************************************************/
static unsigned int skbdump_hook(unsigned int hooknum,
								struct sk_buff *skb,
								const struct net_device *in,
								const struct net_device *out,
								int (*okfn)(struct sk_buff*))
{
	struct iphdr *iph = NULL;
    struct tcphdr *th = NULL;
    struct udphdr *uh = NULL;
    struct nf_conntrack_tuple *st = NULL, *dt = NULL;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = NULL;

    if(!atomic_read(&s_dump_enable))
        return NF_ACCEPT;

        /* 已经确定在跟踪状态的包，不再进行判断了 */
    if ( skb_extdata(skb)->skbdump_flag || !(DUMP_LSKB & s_filter.level) )
        return NF_ACCEPT;
    ct = nf_ct_get(skb, &ctinfo);
    if(ct == NULL)
        return NF_ACCEPT;

    st = &ct->tuplehash[0].tuple;
    dt = &ct->tuplehash[1].tuple;

    iph = ip_hdr(skb);
    if ( unlikely(NULL == iph) )
        return NF_ACCEPT;

    if ( MATCH != match_skb(skb) )
        return NF_ACCEPT;

    switch(iph->protocol)
    {
    case IPPROTO_TCP:
    {
        if ( !pskb_may_pull(skb, IPH_LEN(iph) + sizeof(*th)) )
        {
            st = &ct->tuplehash[CTINFO2DIR(ctinfo)].tuple;
            printk("\n[%s:%d] TCP skb=%p,%pI4:%u->%pI4:%u "
                   "!pskb_may_pull len=%u datalen=%u tail=%lu end=%lu\n"
                   , __FUNCTION__, __LINE__, skb
                   , &iph->saddr
                   , ntohs(st->src.u.tcp.port)
                   , &iph->daddr
                   , ntohs(st->dst.u.tcp.port)
                   , skb->len, skb->data_len
                   , (ulong)skb->tail, (ulong)skb->end);
            return NF_ACCEPT;
        }
        iph = ip_hdr(skb);

        skb_extdata(skb)->skbdump_flag = s_filter.level;
        th = (struct tcphdr *)((char*)iph + IPH_LEN(iph));

        /* 匹配时打堆栈 */
        //dumpstack_skb();

        printk("\n[%s:%d] TCP skb=%p,src:%pI4:%u->dst:%pI4:%u, %c,seq:%u\n"
               , __FUNCTION__, __LINE__, skb
               , &iph->saddr, ntohs(th->source)
               , &iph->daddr, ntohs(th->dest)
               , tcp_flag(th), ntohl(th->seq));

        /* 注意: 不要在此函数中添加过多的信息输出，详细的信息输出放在dump_skb中 */
    }

    break;
    case IPPROTO_UDP:
    {
        if ( !pskb_may_pull(skb, IPH_LEN(iph) + sizeof(*uh)) )
        {
            st = &ct->tuplehash[CTINFO2DIR(ctinfo)].tuple;
            printk("\n[%s:%d] UDP skb=%p,%pI4:%u->%pI4:%u "
                   "!pskb_may_pull len=%u datalen=%u tail=%lu end=%lu\n"
                   , __FUNCTION__, __LINE__, skb
                   , &iph->saddr
                   , ntohs(st->src.u.udp.port)
                   , &iph->daddr
                   , ntohs(st->dst.u.udp.port)
                   , skb->len, skb->data_len
                   , (ulong)skb->tail, (ulong)skb->end);
            return NF_ACCEPT;
        }
        iph = ip_hdr(skb);
        skb_extdata(skb)->skbdump_flag = s_filter.level;
        uh = (struct udphdr *)((char*)iph + IPH_LEN(iph));

        /* 匹配时打堆栈 */
        //dumpstack_skb();

        printk("\n[%s:%d] UDP skb=%p,src:%pI4:%u->dst:%pI4:%u\n",
               __FUNCTION__, __LINE__, skb
               , &iph->saddr, ntohs(uh->source)
               , &iph->daddr, ntohs(uh->dest));
    }
    break;
    case IPPROTO_ICMP:
    {
        skb_extdata(skb)->skbdump_flag = s_filter.level;
        /* 匹配时打堆栈 */
        //dumpstack_skb();

        printk("\n[%s:%d] ICMP skb=%p,src:%pI4->dst:%pI4\n",
               __FUNCTION__, __LINE__, skb, &iph->saddr, &iph->daddr);
    }
    break;
    default:
        break;
    }

    return NF_ACCEPT;
}


static struct nf_hook_ops s_hook_ops[] __read_mostly = {
	{
		.owner = THIS_MODULE,
		.hook = skbdump_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
		.owner = THIS_MODULE,
		.hook = skbdump_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	}
};

static int proc_skbdump_read(char *page, char **start, off_t off, int count,
							int *eof, void *data)
{
	int len = 0;

    len += snprintf(page+len, count-len,
                    "Usage: echo \"cmd1=value1 cmd2=value2 ...\" >/proc/skbdump\n");

    len += snprintf(page+len, count-len,
                    "command:\n");

    len += snprintf(page+len, count-len,
                    "       \"enable=0|1\" enable or disable the skbdump driver\n"
                    "       \"prot=tcp|udp|icmp\" filter the protocol\n"
                    "       \"ip=x.x.x.x\" filter the ipv4 address\n"
                    "       \"port=xx\" filter the port of the tcp protocol or udp protocol\n"
                   );
    len += snprintf(page+len, count-len,
                    "       \"level=[0-%d] %d-DUMP_L2 %d-DUMP_L3 "
                    "%d-DUMP_HOOK %d-DUMP_L4 %d-DUMP_EXPECT %d-DUMP_ALL\"\n"
                    , DUMP_LALL, DUMP_L2, DUMP_L3
                    , DUMP_HOOK_L3, DUMP_L4, DUMP_L_EXPECT, DUMP_LALL);
    len += snprintf(page+len, count-len,
                    "       \"verbose=[0-%d] %d-skb %d-nfct %d-protocol "
                    "%d-expect %d-route %d-bridge %d-all\" show more information\n"
                    , VERBOSE_EN_ALL, VERBOSE_EN_SKB, VERBOSE_EN_NFCT
                    , VERBOSE_EN_PROTO, VERBOSE_EN_EXPECT, VERBOSE_EN_ROUTE
                    , VERBOSE_EN_BRIDGE, VERBOSE_EN_ALL
                   );
    len += snprintf(page+len, count-len,
                    "       \"dumpstack=count\" dump the stack\n"
                    "       \"sock=0|1 saddr=x daddr=x sport=x dport=x\""
                    " trace the sock but only support the tcp protocol\n"
                    "       \"expect=0|1\" trace the expect connection\n"
                    "       \"event=0|1\" trace the nf_conntrack event\n"
                    "       \"nfct prot=x saddr=x daddr=x sport=x dport=x\"\n");

    len += snprintf(page+len, count-len,
                    "eg:    Trace a tcp connection \n"
                    "       echo \"prot=tcp "
                    "ip=200.200.40.71 port=22345\" >/proc/skbdump\n");

    len += snprintf(page+len, count-len,
                    "eg:    Trace the command connection and the data connection of ftp\n"
                    "       echo \"enable=1 level=32 expect=1 event=1 prot=tcp "
                    "ip=200.200.40.71 port=21\" >/proc/skbdump\n");

    len += snprintf(page+len, count-len
                    , "\ncurrent setting:\nenable=%d protocol=%s level=%d ip=%pI4 "
                    "port=%u verbose=%d dumpstack=%d expect=%d event=%d\n"
                    , atomic_read(&s_dump_enable)
                    , IPPROTO_TCP == s_filter.proto
                    ? "TCP"
                    : (IPPROTO_UDP == s_filter.proto
                       ? "UDP" : "ICMP")
                    , s_filter.level
                    , &s_filter.ip, ntohs(s_filter.port)
                    , s_filter.verbose
                    , atomic_read(&s_filter.dumpstack)
                    , s_filter.expect, s_filter.event);
    return len;
}

static int skbdump_nfct_event(struct notifier_block *nb, ulong event, void *data)
{
    const struct nf_conn *ct = (const struct nf_conn*)data;
    if ( !atomic_read(&s_dump_enable) )
        return NOTIFY_DONE;

    if ( MATCH != match_nfct_master(ct) )
    {
        /* 处理事件，为了能够看到没有找到期望连接的连接，因此可以再做一次模糊匹配 */
        if ( !s_filter.expect || MATCH != match_nfct(ct, 1) )
            return NOTIFY_DONE;
    }
    switch(event)
    {
    case IPCONNTRACK_EVENT_INIT:
    case IPCONNTRACK_EVENT_CONFIRM:
    case IPCONNTRACK_EVENT_DESTROY:
        dump_nfct_event(ct, event);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static int register_dumpor(int reg)
{
    static int s_registered = 0;
    int ret = 0;

    if ( !reg && s_registered )
    {
        unregister_sangfor_dump(&s_dump_ops);
        nf_unregister_hooks(s_hook_ops, ARRAY_SIZE(s_hook_ops));
        s_registered = 0;
    }
    else if ( reg && !s_registered )
    {
        /* 注册dump回调，回调部分是主要信息输出点 */
        ret = register_sangfor_dump(&s_dump_ops);
        if ( unlikely(ret < 0) )
        {
            printk(KERN_ERR "register_dump_skb failed %d\n", ret);
            return ret;
        }

        /* 注册钩子，钩子主要负责匹配数据包 */
        ret = nf_register_hooks(s_hook_ops, ARRAY_SIZE(s_hook_ops));
        if ( unlikely(ret < 0) )
        {
            printk(KERN_ERR "register hook failed!\n");
            unregister_sangfor_dump(&s_dump_ops);
            return ret;
        }

        s_registered = 1;
    }

    return 0;
}


static struct notifier_block s_nfct_event =
{
    .notifier_call = skbdump_nfct_event,
};

static int proc_skbdump_write(struct file *file, const char __user *buffer, 
							unsigned long count, void *data)
{
	int enable = -1, event = -1;
	struct dbg_option_t dbg_opt[] =
    {
        {"enable", dbg_parse_int, &enable},

        /* 跟踪的级别，主要有跟踪skb和期望子连接 ；
        ** 而跟踪skb时又分为二层、三层、钩子、四层跟踪 */
        {"level", dbg_parse_int, &s_filter.level},

        /* prot 协议；ip port；这三个主要匹配条件，不支持模糊匹配，
        ** 跟踪多连接协议时，这三个必须匹配主连接 */
        {"prot", dbg_parse_prot, &s_filter.proto},
        {"ip", dbg_parse_ipv4, &s_filter.ip},
        {"port", dbg_parse_port, &s_filter.port},

        /* 是否显示更加详细的信息 ，它有一个参数控制显示哪部分的详情，避免显示信息过多*/
        {"verbose", dbg_parse_int, &s_filter.verbose},

        /* 打开sock的SOCK_DBG选项，目前只支持TCP协议 */
        //{"sock", dbg_sock, NULL},

        /* 查询nfct */
        {"nfct", dbg_nfct, NULL},

        /* 跟踪skb时，是否在匹配时打印堆栈，用于跟踪包的来源，
        ** 它有一个参数控制打印堆栈的次数，避免每个包匹配时都打印 */
        {"dumpstack", dbg_parse_int, &s_filter.dumpstack},

        /* 是否跟踪期望子连接，跟踪期望子连接时ip与port参数为主连接的信息 */
        {"expect", dbg_parse_int, &s_filter.expect},

        /* 是否跟踪nfct事件 */
        {"event", dbg_parse_int, &event},
    };

	char kbuf[MAX_CMD_BUF] = {0};

    if ( count >= MAX_CMD_BUF )
        return (int32_t)count;
    if ( copy_from_user(kbuf, buffer, count) )
        return -EFAULT;

    (void)dbg_get_option(dbg_opt, ARRAY_SIZE(dbg_opt), kbuf, count);

    /* 如果修改了enable选项，则直接修改s_dump_enable */
    if ( enable >= 0 )
    {
        register_dumpor(enable);
        atomic_set(&s_dump_enable, enable ? 1 : 0);
    }
    else if ( !atomic_read(&s_dump_enable) )
    {
        /* 如果没有enable选项，则自动根据level与ip \ port值
        ** 自动开启s_dump_enable，兼容老式skbdump用法
        */
        if ( s_filter.level && s_filter.proto && s_filter.ip && s_filter.port )
        {
            register_dumpor(1);
            atomic_set(&s_dump_enable, 1);
        }
    }

    if ( event > 0 )
    {
        if ( !s_filter.event ) //开启事件通知
        {
            (void)register_conntrack_notifier(&s_nfct_event);
            s_filter.event = 1;
        }
    }
    else if ( 0 == event )
    {
        if ( s_filter.event ) //取消事件处理
        {
            unregister_conntrack_notifier(&s_nfct_event);
            s_filter.event = 0;
        }
    }
    return (int32_t)count;
}

static int __init skbdump_init(void)
{
	int ret = 0;
	struct proc_dir_entry *skbdump_entry = NULL;

	skbdump_entry = create_proc_entry(MODULE_SKBDUMP_PROC, 0, NULL);
	if(!skbdump_entry){
		printk("create proc file failed!");
		goto create_skbdump_proc_failed;
	}

	skbdump_entry->read_proc = proc_skbdump_read;
	skbdump_entry->write_proc = proc_skbdump_write;

	ret = nfhook_init();
	if(ret < 0){
		printk(KERN_ERR "create nflist proc failed!\n");
		goto nfhook_init_failed;
	}

	printk(KERN_INFO "skb_dump module installed\n");
	return 0;
	
nfhook_init_failed:
	remove_proc_entry(MODULE_SKBDUMP_PROC, NULL);
create_skbdump_proc_failed:
	return ret;
}

static void __exit skbdump_exit(void)
{
	remove_proc_entry(MODULE_SKBDUMP_PROC, NULL);
}

module_init(skbdump_init);
module_exit(skbdump_exit);
MODULE_LICENSE("GPL");
