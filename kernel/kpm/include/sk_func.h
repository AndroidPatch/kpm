#ifndef _KPM_KS_FUNC_H
#define _KPM_KS_FUNC_H

#include <linux/kallsyms.h>

#define INIT_USE_KALLSYMS_LOOKUP_NAME

#define skfunc_def(func) (*skf_##func)
#define skfunc(func) skf_##func
#define skfunc_lookup_name(func) skf_##func = (typeof(skf_##func))kallsyms_lookup_name(#func)

#ifdef INIT_USE_KALLSYMS_LOOKUP_NAME
#define skfunc_match(func, name, addr) skfunc_lookup_name(func)
#else
static inline int _s_ksym_local_strcmp(const char *s1, const char *s2)
{
    const unsigned char *c1 = (const unsigned char *)s1;
    const unsigned char *c2 = (const unsigned char *)s2;
    unsigned char ch;
    int d = 0;
    while (1) {
        d = (int)(ch = *c1++) - (int)*c2++;
        if (d || !ch) break;
    }
    return d;
}
#define skfunc_match(func, name, addr) \
    if (!skf_##func && !_s_ksym_local_strcmp(#func, name)) skf_##func = (typeof(skf_##func))addr
#endif

#endif /* _KPM_UTILS_H */
