#ifndef _DBG_OPTION_H
#define _DBG_OPIION_H

typedef int32_t (*parse_fn_t)(const char *, int32_t , int32_t, void *);

/* 选项结构 */
struct dbg_option_t
{
    const char  *name;
    parse_fn_t    parse_fn;
    void        *data;
};

#define     MAX_CMD_BUF     128

/*******************************************************************************
**   参    数:   [in]   opts        选项集
                 [in]   optlen      数组个数
                 [in]   name        当前解析出来的名字
**   功能描述:   匹配相应的选项
**   返 回 值:   返回匹配的选项; NULL failed
**   注    意:   调用者必须保证参数有效性
**   历史记录:
             1.  2012-12-14 create by wangzheng24937.
*******************************************************************************/
static struct dbg_option_t *dbg_match_option(struct dbg_option_t *opts
        , int32_t optlen, const char *name)
{
    int32_t i = 0;

    for ( i = 0; i < optlen; i++ )
    {
        if ( !strcmp(name, opts[i].name) )
        {
            return &opts[i];
        }
    }
    return NULL;
}

/****************************************************************************
**   参  数:     [in]   buf 命令行以\0结束的字符串
                 [in]   buf_len buf的长度
                 [in]   start 从buf的start位开始解析
                 [out]  cmd 解析出的命令字符串
                 [in]   cmd_len cmd的长度
**   描  述:     从命令行中解出一个命令字
**   返回值:     指向buf中cmd的最后一字符的后一个位置; <0 失败; 0 表示成功，且buf解析到了尾
**   注  意:     调用者必须保证参数有效性
**   历史记录:
**       1. 2011-06-09 create by wangzheng24937
****************************************************************************/
static int32_t dbg_get_value(const char *buf, int32_t buf_len
                             , int32_t start, char *cmd, int32_t cmd_len)
{
    int i = 0, j = 0;

    if ( (NULL == buf || NULL == cmd || start >= buf_len) )
    {
        return -1;
    }

    i = start;

    while( '\0' != buf[i] && (isspace(buf[i]) || '=' == buf[i])) i++;

    if ( '\0' == buf[i] ) return -1;

    //查找符号
    while('\0' != buf[i] && '=' != buf[i] && !isspace(buf[i])
            && j < cmd_len )
    {
        cmd[j++] = buf[i++];
    }

    //解出来
    if ( j < cmd_len )
    {
        cmd[j] = '\0';
    }
    else //溢出
    {
        return -1;
    }

    //BUG_ON(strlen(cmd) >= cmd_len);

    if ( '\0' == buf[i] )
    {
        return 0;
    }

    return i + 1;
}

/*******************************************************************************
**   参    数:   [in]   opts    选项集
                 [in]   optcnt  数组个数
                 [in]   buf     命令行
                 [in]   count   命令行长度
**   功能描述:   解析选项
**   返 回 值:   0 successed;<0 failed
**   注    意:   调用者必须保证参数有效性
                1. 解析的数据格式为  "name1=value1 name2=value2 name3=value3"
**   历史记录:
             1.  2012-12-14 create by wangzheng24937.
*******************************************************************************/
static int32_t dbg_get_option(struct dbg_option_t *opts, int32_t optcnt
                              , const char *buf, int32_t count)
{
    char value[MAX_CMD_BUF]={0};
    int32_t start = 0;
    struct dbg_option_t *opt = NULL;

    do
    {
        start = dbg_get_value(buf, count, start, value, sizeof(value) - 1);
        if ( start <= 0 )
        {
            break;
        }

        opt = dbg_match_option(opts, optcnt, value);
        if ( NULL != opt && NULL != opt->parse_fn )
        {
            start = opt->parse_fn(buf, count, start, opt);
        }
    }
    while(start > 0);

    return 0;
}

/*******************************************************************************
**   参    数:   [in]   buf         命令行
                 [in]   count       buf的长度
                 [in]   start       开始的位置
                 [in]   opt         私有数据
**   功能描述:   解析INT型，结果存在opt->data中
**   返 回 值:   返回解析后的位置
**   注    意:
**   历史记录:
             1.  2012-12-14 create by wangzheng24937.
*******************************************************************************/
static int32_t dbg_parse_int(const char *buf, int32_t count
                             , int32_t start, void *opt)
{
    struct dbg_option_t *self = (struct dbg_option_t *)opt;
    int32_t rst = 0;
    char value[MAX_CMD_BUF] = "";

    start = dbg_get_value(buf, count, start, value, sizeof(value));
    if ( start < 0 )
        return start;
    if ( self && self->data )
    {
        if ( 0 == str_to_int(value, &rst) )
        {
            *((int32_t *)(self->data)) = rst;
        }
    }
    return start;
}

/*******************************************************************************
**   参    数:   [in]   buf         命令行
                 [in]   count       buf的长度
                 [in]   start       开始的位置
                 [in]   opt         私有数据
**   功能描述:   解析协议类型，结果存在opt->data中
**   返 回 值:   返回解析后的位置
**   注    意:
**   历史记录:
             1.  2012-12-14 create by wangzheng24937.
*******************************************************************************/
static inline int32_t dbg_parse_prot(const char *buf, int32_t count
                              , int32_t start, void *opt)
{
    struct dbg_option_t *self = (struct dbg_option_t *)opt;
    char value[MAX_CMD_BUF] = "";

    start = dbg_get_value(buf, count, start, value, sizeof(value));
    if ( start < 0 )
        return start;
    if ( self && self->data )
    {
        if ( !strcmp("TCP", value) || !strcmp("tcp", value))
        {
            *((int32_t *)(self->data)) = IPPROTO_TCP;
        }
        else if ( !strcmp("UDP", value) || !strcmp("udp", value))
        {
            *((int32_t *)(self->data)) = IPPROTO_UDP;
        }
        else if ( !strcmp("ICMP", value) || !strcmp("icmp", value))
        {
            *((int32_t *)(self->data)) = IPPROTO_ICMP;
        }
        else if ( !strcmp("ALL", value) || !strcmp("all", value))
        {
            *((int32_t *)(self->data)) = 0;
        }
    }
    return start;
}

/*******************************************************************************
**   参    数:   [in]   buf         命令行
                 [in]   count       buf的长度
                 [in]   start       开始的位置
                 [in]   opt         私有数据
**   功能描述:   解析IP地址，结果存在opt->data中
**   返 回 值:   返回解析后的位置
**   注    意:
**   历史记录:
             1.  2012-12-14 create by wangzheng24937.
*******************************************************************************/
static inline int32_t dbg_parse_ipv4(const char *buf, int32_t count
                                        , int32_t start, void *opt)
{
    struct dbg_option_t *self = (struct dbg_option_t *)opt;
    uint32_t rst = 0;
    char value[MAX_CMD_BUF] = "";

    start = dbg_get_value(buf, count, start, value, sizeof(value));
    if ( start < 0 )
        return start;
    if ( self && self->data )
    {
        if ( 0 == str_to_ipv4(value, &rst) )
        {
            *((uint32_t *)(self->data)) = rst;
        }
    }
    return start;
}

/*******************************************************************************
**   参    数:   [in]   buf         命令行
                 [in]   count       buf的长度
                 [in]   start       开始的位置
                 [in]   opt         私有数据
**   功能描述:   解析端口网络序，结果存在opt->data中
**   返 回 值:   返回解析后的位置
**   注    意:
**   历史记录:
             1.  2012-12-14 create by wangzheng24937.
*******************************************************************************/
static inline int32_t dbg_parse_port(const char *buf, int32_t count
                                        , int32_t start, void *opt)
{
    struct dbg_option_t *self = (struct dbg_option_t *)opt;
    int32_t rst = 0;
    char value[MAX_CMD_BUF] = "";

    start = dbg_get_value(buf, count, start, value, sizeof(value));
    if ( start < 0 )
        return start;
    if ( self && self->data )
    {
        if ( 0 == str_to_int(value, &rst) )
        {
            *((uint16_t *)(self->data)) = htons(rst);
        }
    }
    return start;
}


#endif
