/*
 * Cerberus rule matching helpers.
 *
 * Deny-rule and sandbox/allowlist decisions against
 * the rule key currently stored in a scoped_rule_key.
 */
#ifndef CERBERUS_RULES_BPF_H
#define CERBERUS_RULES_BPF_H


/*
 * Check global, process and UID deny rules
 * against the rule key currently in skey->rule.
 *
 * Returns 1 if a rule matched (event already emitted).
 */
static __always_inline int check_deny_rules(
    struct scoped_rule_key *skey,
    __u32 uid,
    int denied)
{
    struct rule_value *rule;

    /*
     * Global rule.
     */
    rule = bpf_map_lookup_elem(
        &blocklist,
        skey->rule
    );

    if (rule)
    {
        emit_event(
            skey->rule,
            rule->type,
            denied
        );

        return 1;
    }


    /*
     * Process rule.
     */
    bpf_get_current_comm(
        skey->comm,
        sizeof(skey->comm)
    );

    skey->uid = CERBERUS_UID_ANY;

    rule = bpf_map_lookup_elem(
        &scoped_rules,
        skey
    );

    if (rule)
    {
        emit_event(
            skey->rule,
            rule->type,
            denied
        );

        return 1;
    }


    /*
     * UID rule.
     */
    __builtin_memset(
        skey->comm,
        0,
        sizeof(skey->comm)
    );

    skey->uid = uid;

    rule = bpf_map_lookup_elem(
        &scoped_rules,
        skey
    );

    if (rule)
    {
        emit_event(
            skey->rule,
            rule->type,
            denied
        );

        return 1;
    }

    return 0;
}


/*
 * Is the current process sandboxed?
 */
static __always_inline int process_is_sandboxed(
    struct scoped_rule_key *skey)
{
    bpf_get_current_comm(
        skey->comm,
        sizeof(skey->comm)
    );

    return bpf_map_lookup_elem(
        &sandboxed,
        skey->comm
    ) != 0;
}


/*
 * Does the rule key currently in skey->rule match
 * an allowlist entry for the current process?
 */
static __always_inline int allow_matches(
    struct scoped_rule_key *skey)
{
    skey->uid = CERBERUS_UID_ANY;

    return bpf_map_lookup_elem(
        &allowlist,
        skey
    ) != 0;
}


#endif /* CERBERUS_RULES_BPF_H */
