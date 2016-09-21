#ifndef _DBG_OPTION_H
#define _DBG_OPIION_H

typedef int32_t (*parse_fn_t)(const char *, int32_t , int32_t, void *);

/* ѡ��ṹ */
struct dbg_option_t
{
    const char  *name;
    parse_fn_t    parse_fn;
    void        *data;
};

#define     MAX_CMD_BUF     128

/*******************************************************************************
**   ��    ��:   [in]   opts        ѡ�
                 [in]   optlen      �������
                 [in]   name        ��ǰ��������������
**   ��������:   ƥ����Ӧ��ѡ��
**   �� �� ֵ:   ����ƥ���ѡ��; NULL failed
**   ע    ��:   �����߱��뱣֤������Ч��
**   ��ʷ��¼:
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
**   ��  ��:     [in]   buf ��������\0�������ַ���
                 [in]   buf_len buf�ĳ���
                 [in]   start ��buf��startλ��ʼ����
                 [out]  cmd �������������ַ���
                 [in]   cmd_len cmd�ĳ���
**   ��  ��:     ���������н��һ��������
**   ����ֵ:     ָ��buf��cmd�����һ�ַ��ĺ�һ��λ��; <0 ʧ��; 0 ��ʾ�ɹ�����buf��������β
**   ע  ��:     �����߱��뱣֤������Ч��
**   ��ʷ��¼:
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

    //���ҷ���
    while('\0' != buf[i] && '=' != buf[i] && !isspace(buf[i])
            && j < cmd_len )
    {
        cmd[j++] = buf[i++];
    }

    //�����
    if ( j < cmd_len )
    {
        cmd[j] = '\0';
    }
    else //���
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
**   ��    ��:   [in]   opts    ѡ�
                 [in]   optcnt  �������
                 [in]   buf     ������
                 [in]   count   �����г���
**   ��������:   ����ѡ��
**   �� �� ֵ:   0 successed;<0 failed
**   ע    ��:   �����߱��뱣֤������Ч��
                1. ���������ݸ�ʽΪ  "name1=value1 name2=value2 name3=value3"
**   ��ʷ��¼:
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
**   ��    ��:   [in]   buf         ������
                 [in]   count       buf�ĳ���
                 [in]   start       ��ʼ��λ��
                 [in]   opt         ˽������
**   ��������:   ����INT�ͣ��������opt->data��
**   �� �� ֵ:   ���ؽ������λ��
**   ע    ��:
**   ��ʷ��¼:
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
**   ��    ��:   [in]   buf         ������
                 [in]   count       buf�ĳ���
                 [in]   start       ��ʼ��λ��
                 [in]   opt         ˽������
**   ��������:   ����Э�����ͣ��������opt->data��
**   �� �� ֵ:   ���ؽ������λ��
**   ע    ��:
**   ��ʷ��¼:
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
**   ��    ��:   [in]   buf         ������
                 [in]   count       buf�ĳ���
                 [in]   start       ��ʼ��λ��
                 [in]   opt         ˽������
**   ��������:   ����IP��ַ���������opt->data��
**   �� �� ֵ:   ���ؽ������λ��
**   ע    ��:
**   ��ʷ��¼:
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
**   ��    ��:   [in]   buf         ������
                 [in]   count       buf�ĳ���
                 [in]   start       ��ʼ��λ��
                 [in]   opt         ˽������
**   ��������:   �����˿������򣬽������opt->data��
**   �� �� ֵ:   ���ؽ������λ��
**   ע    ��:
**   ��ʷ��¼:
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
