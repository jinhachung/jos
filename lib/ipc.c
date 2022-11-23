// User-level IPC library routines

#include <inc/lib.h>

// Receive a value via IPC and return it.
// If 'pg' is nonnull, then any page sent by the sender will be mapped at
//  that address.
// If 'from_env_store' is nonnull, then store the IPC sender's envid in
//  *from_env_store.
// If 'perm_store' is nonnull, then store the IPC sender's page permission
//  in *perm_store (this is nonzero iff a page was successfully
//  transferred to 'pg').
// If the system call fails, then store 0 in *fromenv and *perm (if
//  they're nonnull) and return the error.
// Otherwise, return the value sent by the sender
//
// Hint:
//   Use 'thisenv' to discover the value and who sent it.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value, since that's
//   a perfectly valid place to map a page.)
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
    // LAB 4: Your code here.
    int errno;
    // if pg is nonNULL, map to that address
    // if pg is NULL, pass value that sys_ipc_recv will do nothing about --> UTOP
    if(!pg)
        pg = (void*) UTOP;
    /*
    if (!from_env_store)
        panic("from_env_store is NULL\n");
    if (!perm_store)
        panic("perm_store is NULL\n");
    */
    errno = sys_ipc_recv(pg);
    if (errno < 0) {
        // set to 0 and return error
        if (from_env_store)
            *from_env_store = 0;
        if (perm_store)
            *perm_store =0;
        return errno;
    }
    // store values and return value
    if (from_env_store)
        *from_env_store = thisenv->env_ipc_from;
    if (perm_store)
        *perm_store = thisenv->env_ipc_perm;
    return thisenv->env_ipc_value;
}

// Send 'val' (and 'pg' with 'perm', if 'pg' is nonnull) to 'toenv'.
// This function keeps trying until it succeeds.
// It should panic() on any error other than -E_IPC_NOT_RECV.
//
// Hint:
//   Use sys_yield() to be CPU-friendly.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value.)
void
ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
    // LAB 4: Your code here.
    int errno;
    // if pg is NULL, pass value that sys_ipc_recv will do nothing about --> UTOP
    if(!pg)
        pg = (void*)UTOP;

    while (1) {
        errno = sys_ipc_try_send(to_env, (uint64_t)val, pg, perm);
        if (errno < 0) {
            if (errno != -E_IPC_NOT_RECV)
                panic("sys_ipc_try_send returns error other than -E_IPC_NOT_RECV\n");
            // sys_yield upon error to be CPU-friendly
            if (errno == -E_IPC_NOT_RECV)
                sys_yield();
        } else
            return;
    }
}


// Find the first environment of the given type.  We'll use this to
// find special environments.
// Returns 0 if no such environment exists.
envid_t
ipc_find_env(enum EnvType type)
{
    int i;
    for (i = 0; i < NENV; i++) {
        if (envs[i].env_type == type)
            return envs[i].env_id;
    }
    return 0;
}
