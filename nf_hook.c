#include "skbdump.h"
#include <linux/seq_file.h>

#define PROC_NFHOOK "nfhook"
#define PROC_NFLIST "nflist"

#define nflist_pos_hash(pos) ((pos) & 0x0000ffff)
#define nflist_pos_lcnt(pos) ((pos) >> 16)
#define nflist_pos_hash_inc(pos)	 ((pos) = nflist_pos_hash(pos) + 1)
/* 移动链表个数 */
#define nflist_pos_lcnt_inc(pos)    \
        ((pos) = ((nflist_pos_lcnt(pos) + 1) << 16) | nflist_pos_hash(pos) )

/* 设置链表个数 */
#define nflist_pos_lcnt_set(pos, cnt) \
        ((pos) = ((cnt) << 16) | nflist_pos_hash(pos))

static struct proc_dir_entry *s_proc_nfhook = NULL;

static void *nflist_start(struct seq_file *seq, loff_t *pos)
{
    loff_t *priv = (loff_t*)&seq->private;

    //dbg_pos(priv);
    if ( nflist_pos_hash(*priv) >= (NFPROTO_NUMPROTO * NF_MAX_HOOKS) )
        return NULL;

    return priv;
}

static void *nflist_next(struct seq_file *s, void *v, loff_t *pos)
{
    //dbg_pos(v);
    if (nflist_pos_hash(*(loff_t*)v) >= (NFPROTO_NUMPROTO * NF_MAX_HOOKS))
        return NULL;

    return v;
}

static void nflist_stop(struct seq_file *s, void *v)
{
    //dbg_pos(v);
    //UNUSE_ARG(s);
    //UNUSE_ARG(v);
}

static int nflist_show(struct seq_file *s, void *v)
{
    loff_t *pos = v;
    struct nf_hook_ops *elem = NULL;
    int ret = 0;
    int i = 0;
    loff_t hash = nflist_pos_hash(*pos); /* pos: 0-15位，用于记录其槽位，16-31位记录list_head下链表个数 */
    loff_t prot = (hash / NF_MAX_HOOKS);
    loff_t hook = (hash % NF_MAX_HOOKS);
    loff_t num = nflist_pos_lcnt(*pos);

    //dbg_pos(pos);
    list_for_each_entry(elem, &nf_hooks[prot][hook], list) {
        if ( i < num )
            continue;
        i++;
        ret = seq_printf(s
                         , "pf=%-6s hook=%-8s pri=%-11d fn=%-32s owner=%s\n"
                         , nfproto_str(elem->pf)
                         , hook_str(elem->hooknum), elem->priority
                         , get_symbol((ulong)elem->hook)
                         , elem->owner ? elem->owner->name : "unkown");
        if ( ret < 0 )
        {
            /* 回退本次已经输出的节点 */
            nflist_pos_lcnt_set(*pos, num);
            //dbg_pos(pos);
            return ret;
        }
        nflist_pos_lcnt_inc(*pos);
    }
    //本次循环后，开始移入下一个协议
    nflist_pos_hash_inc(*pos);

    return 0;
}

static struct seq_operations seq_nflist_ops = {
	.start = nflist_start,
	.stop = nflist_stop,
	.next = nflist_next,
	.show = nflist_show,
};

static int nflist_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &seq_nflist_ops);
}

static struct file_operations proc_nflist_fops = {
	.owner = THIS_MODULE,
	.open = nflist_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

int nfhook_init(void)
{
	int ret = 0;
	struct proc_dir_entry *proc_nflist = NULL;
	
	s_proc_nfhook = create_proc_entry(PROC_NFHOOK, S_IFDIR, NULL);
	if(!s_proc_nfhook){
		printk("create nfhook proc failed\n");
		goto create_nfhook_proc_failed;
	}

	proc_nflist = create_proc_entry(PROC_NFLIST, 0, s_proc_nfhook);
	if(!proc_nflist){
		printk("create nflist proc failed\n");
		goto create_nflist_proc_failed;
	}

	proc_nflist->proc_fops = &proc_nflist_fops;

	return 0;

create_nflist_proc_failed:
	remove_proc_entry(PROC_NFHOOK, NULL);
create_nfhook_proc_failed:
	return ret;
}

void nfhook_cleanup(void)
{
	remove_proc_entry(PROC_NFLIST, s_proc_nfhook);
	remove_proc_entry(PROC_NFHOOK, NULL);
}
