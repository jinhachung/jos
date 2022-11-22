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
    panic("duppage not implemented");
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
    panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
    panic("sfork not implemented");
    return -E_INVAL;
}
