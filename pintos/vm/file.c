/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "lib/debug.h"

static bool file_backed_swap_in(struct page* page, void* kva);
static bool file_backed_swap_out(struct page* page);
static void file_backed_destroy(struct page* page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page* page, enum vm_type type, void* kva)
{
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page* file_page = &page->file;

    struct lazy_load_aux* lazy_load_aux = (struct lazy_load_aux*)page->uninit.aux;
    file_page->file = lazy_load_aux->file;
    file_page->ofs = lazy_load_aux->ofs;
    file_page->read_bytes = lazy_load_aux->page_read_bytes;
    file_page->zero_bytes = lazy_load_aux->page_zero_bytes;
    return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page* page, void* kva)
{
    struct file_page* file_page = &page->file;
    return lazy_load_segment(page, file_page);
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page* page)
{
    struct file_page* file_page = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page* page)
{
    struct file_page* file_page = &page->file;
    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(file_page->file, page->va, file_page->read_bytes, file_page->ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, 0);
    }
    pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void* do_mmap(void* addr, size_t length, int writable, struct file* file, off_t offset)
{
    struct file* f = file_reopen(file);
    void* start_addr = addr; // 매핑 성공 시 파일이 매핑된 가상주소 반환하는 데 사용

    int total_page_count = length / PGSIZE;
    if (length % PGSIZE != 0)
        total_page_count++;

    size_t f_len = file_length(f);
    size_t read_bytes;

    if (f_len < length) {
        read_bytes = f_len;
    } else {
        read_bytes = length;
    }

    size_t zero_bytes = 0;
    size_t offset_in_page = 0;
    offset_in_page = read_bytes % PGSIZE;
    zero_bytes = PGSIZE - offset_in_page;

    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(addr) == 0);
    ASSERT(offset % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_load_aux* lazy_load_aux = malloc(sizeof(struct lazy_load_aux));
        if (lazy_load_aux == NULL) {
            file_close(f);
            return NULL;
        }

        lazy_load_aux->file = f;
        lazy_load_aux->ofs = offset;
        lazy_load_aux->page_read_bytes = page_read_bytes;
        lazy_load_aux->page_zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, lazy_load_aux)) {
            file_close(f);
            free(lazy_load_aux);
            return NULL;
        }
        struct page* p = spt_find_page(&thread_current()->spt, addr);
        p->mapped_page_count = total_page_count;

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        addr += PGSIZE;
        offset += page_read_bytes;
    }
    return start_addr;
}

/* Do the munmap */
void do_munmap(void* addr)
{
    struct supplemental_page_table* spt = &thread_current()->spt;
    struct page* p = spt_find_page(spt, addr);
    struct file* f = p->file.file;
    int count = p->mapped_page_count;
    for (int i = 0; i < count; i++) {
        if (p)
            destroy(p);
        addr += PGSIZE;
        p = spt_find_page(spt, addr);
    }
    file_close(f);
}
