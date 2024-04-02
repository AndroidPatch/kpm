#ifndef _POLICYDB_H
#define _POLICYDB_H

#define SELINUX_MAGIC 0xf97cff8c
#define POLICYDB_MAGIC SELINUX_MAGIC
#define POLICYDB_STRING "SE Linux"

#define POLICYDB_CONFIG_MLS 1
#define POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE (1 << 31)
#define POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH (1 << 30)

/*
 * config offset:
 *   __le32(POLICYDB_MAGIC) + __le32(POLICYDB_STRING_LEN) +
 *   char[POLICYDB_STRING_LEN] + __le32(policyvers)
 */
#define POLICYDB_CONFIG_OFFSET (2 * sizeof(__le32) + strlen(POLICYDB_STRING) + sizeof(__le32))

struct _policy_file
{
    char *data;
    size_t len;
};

struct _policydb
{
    int mls_enabled;
    int android_netlink_route;
    int android_netlink_getneigh;
};

#endif // _POLICYDB_H
