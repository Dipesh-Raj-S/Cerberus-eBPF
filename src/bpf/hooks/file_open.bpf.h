/*
 * Cerberus file access control hook.
 *
 * Attached to the Linux Security Module file_open
 * hook, this program decides whether a file open
 * is allowed, reported only, or denied.
 */
#ifndef CERBERUS_HOOK_FILE_OPEN_BPF_H
#define CERBERUS_HOOK_FILE_OPEN_BPF_H


SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file)
{
    struct scoped_rule_key skey = {};

    struct dentry *dentry;
    struct qstr parent_name;
    struct qstr base_name;

    __u32 zero = 0;
    __u32 uid;
    __u8 *mode;
    int denied;
    int sandbox;

    /*
     * Get the file's dentry.
     */
    dentry = BPF_CORE_READ(
        file,
        f_path.dentry
    );

    if (!dentry)
        return 0;

    base_name = BPF_CORE_READ(
        dentry,
        d_name
    );

    parent_name = BPF_CORE_READ(
        dentry,
        d_parent,
        d_name
    );


    /*
     * Decide whether matches are denied or
     * only reported.
     */
    mode = bpf_map_lookup_elem(
        &policy_mode,
        &zero
    );

    denied = (
        mode &&
        *mode == CERBERUS_MODE_ENFORCE
    );

    uid = bpf_get_current_uid_gid();

    sandbox = process_is_sandboxed(&skey);


    /*
     * PATH rule form.
     */
    if (parent_name.name)
    {
        build_path_key(
            skey.rule,
            &parent_name,
            &base_name
        );

        /*
         * A sandboxed process is allowed as soon as
         * either key form appears in its allowlist.
         */
        if (sandbox && allow_matches(&skey))
            return 0;

        if (
            !sandbox &&
            check_deny_rules(&skey, uid, denied))
        {
            return denied ? -EPERM : 0;
        }
    }


    /*
     * NAME rule form.
     */
    build_name_key(
        skey.rule,
        &base_name
    );

    if (sandbox)
    {
        if (allow_matches(&skey))
            return 0;

        /*
         * Default-deny: the sandboxed process tried
         * to open something that is not allowlisted.
         */
        emit_event(
            skey.rule,
            CERBERUS_RULE_SANDBOX,
            denied
        );

        return denied ? -EPERM : 0;
    }

    if (check_deny_rules(&skey, uid, denied))
        return denied ? -EPERM : 0;


    /*
     * No rule matched: allow the operation.
     */
    return 0;
}


#endif /* CERBERUS_HOOK_FILE_OPEN_BPF_H */
