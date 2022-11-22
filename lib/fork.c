// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW     0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
    void *addr = (void *) utf->utf_fault_va;
    uint32_t err = utf->utf_err;
    int r;

    // Check that the faulting access was (1) a write, and (2) to a
    // copy-on-write page.  If not, panic.
    // Hint:
    //   Use the read-only page table mappings at uvpt
    //   (see <inc/memlayout.h>).

    // LAB 4: Your code here.
    // look up PTE by referencing UVPT
    pte_t pte = uvpt[(uint64_t)addr / PGSIZE];
    // check if CoW page
    if (!(pte & PTE_COW))
        panic("pgfault is not CoW\n");
    // TODO: check if write
    if (0)
        panic("pgfault is not a write\n");

    // Allocate a new page, map it at a temporary location (PFTEMP),
    // copy the data from the old page to the new page, then move the new
    // page to the old page's address.
    // Hint:
    //   You should make three system calls.
    //   No need to explicitly delete the old page's mapping.

    // LAB 4: Your code here.
    // allocate new page, perm: PTE_W and PTE_U --> PTE_USER for syscalls
    // use temporary location PFTEMP
    if (sys_page_alloc(0, (void *)PFTEMP, PTE_USER) < 0)
        panic("sys_page_alloc failed\n");
    // copy data from old page to new page
    memcpy((void *)PFTEMP, (const void *)(ROUNDDOWN(addr, PGSIZE)), (size_t)PGSIZE);
    // move new page to the old page's address
    if (sys_page_map(0, (void *)PFTEMP, 0, (void *)ROUNDDOWN(addr, PGSIZE), PTE_USER) < 0)
        panic("sys_page_map failed\n");
    // TODO: remove temporary location with 'third' syscall?
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
    int r;

    // LAB 4: Your code here.
    pte_t pte = uvpt[pn];
    // if page is writable or CoW, create mapping as CoW
    if ((pte & PTE_W) || (pte & PTE_COW)) {
        // unset writable and set as CoW only;
        pte = pte & (~PTE_W);
        pte = pte | PTE_COW;
        // remap current environment's page as new PTE as well
        if (sys_page_map(0, (void *)(uint64_t)(pn * PGSIZE), 0, (void *)(uint64_t)(pn * PGSIZE), (int)(pte & PTE_USER)) < 0)
            panic("sys_page_map failed\n");
    }
    // map as PTE
    if (sys_page_map(0, (void *)(uint64_t)(pn * PGSIZE), envid, (void *)(uint64_t)(pn * PGSIZE), (int)(pte & PTE_USER)) < 0)
        panic ("sys__page_map failed\n");

    return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
    // LAB 4: Your code here.
    envid_t env;
    
    // 1. set pgfault as C-level page fault handler, using set_pgfault_handler
    set_pgfault_handler(pgfault);
    
    // 2. parent calls sys_exofork to create child environment
    env = sys_exofork();
    if (env < 0)
        panic("sys_exofork failed\n");
    if (env == 0) {
        // child
        // 'remember to fix thisenv in the child process'
        thisenv = &(envs[ENVX(sys_getenvid())]);
    } else {
        // parent
        // 3. - (a) for each writable or CoW pages in address below UTOP, call duppage
        // TODO: check order issue described in document
        // TODO: fork() also needs to handle pages that are present, but not writable or copy-on-write
        // jchung: but duppage handles other cases so maybe this is okay
        for (uint64_t va = (uint64_t)(USTACKTOP - PGSIZE); va >= (uint64_t)UTEXT; va -= PGSIZE) {
            // scan all pages, and skip to next if no mapping exists, instead of traversing deeper
            // using variables and functions from inc/memlayout.h and inc/mmu.h
            if (uvpml4e[VPML4E(va)] & PTE_P) {
                if (uvpde[VPDPE(va)] & PTE_P) {
                    if (uvpd[VPD(va)] & PTE_P) {
                        if (uvpt[VPN(va)] & PTE_P)
                            duppage(env, (unsigned)(VPN(va)));
                        else
                            va -= (1 << PTXSHIFT); // -= 4KB, not present in uvpt
                    } else
                        va -= (1 << PDXSHIFT); // -= 2MB, not present in uvpd
                } else
                    va -= (1 << PDPESHIFT); // -= 1GB, not present in uvpde
            }
        }
        // 3. - (b) allocate fresh page in child for exception stack
        if (sys_page_alloc(env, (void *)(USTACKTOP - PGSIZE), PTE_USER) < 0)
            panic("sys_page_alloc failed\n");
        // 4. sets user page fault entrypoint for child
        if (sys_env_set_pgfault_upcall(env, thisenv->env_pgfault_upcall) < 0)
            panic("sys_env_set_pgfault_upcall failed\n");
        // 5. mark child as runnable
        if (sys_env_set_status(env, ENV_RUNNABLE) < 0)
            panic("sys_env_set_status failed\n");
    }
    // 0 for child, positive for parent
    return env;
}

// Challenge!
int
sfork(void)
{
    panic("sfork not implemented");
    return -E_INVAL;
}
