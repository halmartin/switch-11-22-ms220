#include <linux/module.h>
#include <linux/types.h>
#include <linux/click_offload.h>
#include <linux/init.h>
#include <linux/netdevice.h>

/*
 * click offloader interfaces
 */
static struct click_offloader_operations *offloader_ops = NULL;

int register_click_offloader_ops(const struct click_offloader_operations *ops)
{
    if (ops->create_ipv4_rule == NULL || ops->destroy_ipv4_rule == NULL)
        return -EINVAL;

    offloader_ops = (struct click_offloader_operations *)ops;
    return 0;
}
EXPORT_SYMBOL(register_click_offloader_ops);

void unregister_click_offloader_ops(void)
{
    offloader_ops = NULL;
}
EXPORT_SYMBOL(unregister_click_offloader_ops);

bool click_offloader_enabled(void)
{
    return offloader_ops;
}
EXPORT_SYMBOL(click_offloader_enabled);

int click_offloader_create_ipv4_rule(struct click_ipv4_rule_msg *msg)
{
    if (offloader_ops && offloader_ops->create_ipv4_rule && msg)
        return offloader_ops->create_ipv4_rule(msg);

    return -1;
}
EXPORT_SYMBOL(click_offloader_create_ipv4_rule);

int click_offloader_destroy_ipv4_rule(struct click_ipv4_rule_msg *msg)
{
    if (offloader_ops && offloader_ops->destroy_ipv4_rule && msg)
        return offloader_ops->destroy_ipv4_rule(msg);

    return -1;
}
EXPORT_SYMBOL(click_offloader_destroy_ipv4_rule);

/*
 * click offloader (qca-nss clickmgr) event notification
 */
static click_offload_event_cb_t click_offload_event_cb = NULL;
static void *click_offload_data = NULL;
int register_click_offload_event_cb(click_offload_event_cb_t cb, void *data)
{
    if (cb == NULL) {
        return -EINVAL;
    }
    click_offload_event_cb = cb;
    click_offload_data = data;
    return 0;
}
EXPORT_SYMBOL(register_click_offload_event_cb);

void unregister_click_offload_event_cb(void)
{
    click_offload_event_cb = NULL;
    click_offload_data = NULL;
}
EXPORT_SYMBOL(unregister_click_offload_event_cb);

void click_offloader_event_notify(struct click_offload_event *event)
{
    if (click_offload_event_cb && click_offload_data)
        click_offload_event_cb(event, click_offload_data);
}
EXPORT_SYMBOL(click_offloader_event_notify);

#ifdef CONFIG_BONDING
extern int bond_skb_realdev(struct sk_buff *skb, struct net_device *dev, char *real_dev);
#endif
bool click_offload_bond_realdev_name(struct sk_buff *skb, const char *bond_dev, char *real_dev)
{
#ifdef CONFIG_BONDING
    struct net_device *dev = dev_get_by_name(&init_net, bond_dev);
    if (!dev)
        return false;

    /*
     * find possible real device from bond device for nss flow offload use
     */
    if ((dev->flags & IFF_MASTER) && (dev->priv_flags & IFF_BONDING)) {
        if (bond_skb_realdev_name(skb, dev, real_dev)) {
            dev_put(dev);
            return false;
        }
    } else {
        strlcpy(real_dev, dev->name, IFNAMSIZ);
    }

    dev_put(dev);
    return true;
#else
    return false;
#endif
}
EXPORT_SYMBOL(click_offload_bond_realdev_name);
