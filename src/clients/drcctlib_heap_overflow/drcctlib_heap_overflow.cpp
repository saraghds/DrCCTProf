/*
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstddef>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"
#include "drwrap.h"
#include <map>
#include <vector>
#include <algorithm>
using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("heap_overflow", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("heap_overflow", format, ##args)

static int tls_idx;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, type, offs) *(type **)TLS_SLOT(tls_base, offs)
#define MINSERT instrlist_meta_preinsert
#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#endif
#define MALLOC_ROUTINE_NAME IF_WINDOWS_ELSE("HeapAlloc", "malloc")
#define FREE_ROUTINE_NAME "free"
#ifdef SHOW_RESULTS
#endif
#ifdef WINDOWS
#    define IF_WINDOWS_ELSE(x, y) x
#else
#    define IF_WINDOWS_ELSE(x, y) y
#endif

static uint malloc_oom;
static size_t max_malloc;
static void *max_lock; /* to synch writes to max_malloc */

typedef struct _mem_ref_t {
    app_pc addr;
    size_t size;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;

typedef struct _red_map_item {
    app_pc malloc_addr;
    context_handle_t ctxt_hndl;
} red_map_item;

size_t original_allocation_size;
std::map<app_pc, red_map_item> redmap;
std::vector<int64_t> heap_overflow;

#define TLS_MEM_REF_BUFF_SIZE 100
#define TOP_REACH_NUM_SHOW 100
#define MAX_CLIENT_CCT_PRINT_DEPTH 10

static file_t gTraceFile;

static void
pre_malloc(void *wrapcxt, OUT void **user_data);
static void
post_malloc(void *wrapcxt, void *user_data);
static void
pre_free(void *wrapcxt, OUT void **user_data);
static void
post_free(void *wrapcxt, void *user_data);

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    DRCCTLIB_PRINTF("module_load_event");

    app_pc towrap_malloc = (app_pc)dr_get_proc_address(mod->handle, MALLOC_ROUTINE_NAME);
    if (towrap_malloc != NULL) {
        drwrap_wrap(towrap_malloc, pre_malloc, post_malloc);
        // #ifdef SHOW_RESULTS
        //         bool ok =
        // #endif
        //             drwrap_wrap(towrap, wrap_pre, wrap_post);
        // #ifdef SHOW_RESULTS
        //         if (ok) {
        //             dr_fprintf(STDERR, "<wrapped " MALLOC_ROUTINE_NAME " @" PFX "\n",
        //             towrap);
        //         } else {
        //             /* We expect this w/ forwarded exports (e.g., on win7 both
        //              * kernel32!HeapAlloc and kernelbase!HeapAlloc forward to
        //              * the same routine in ntdll.dll)
        //              */
        //             dr_fprintf(STDERR,
        //                        "<FAILED to wrap " MALLOC_ROUTINE_NAME " @" PFX
        //                        ": already wrapped?\n",
        //                        towrap);
        //         }
        // #endif
    }

    app_pc towrap_free = (app_pc)dr_get_proc_address(mod->handle, FREE_ROUTINE_NAME);
    if (towrap_free != NULL) {
        drwrap_wrap(towrap_free, pre_free, post_free);
    }
}

static void
pre_malloc(void *wrapcxt, OUT void **user_data)
{
    DRCCTLIB_PRINTF("pre_malloc");

    /* malloc(size) or HeapAlloc(heap, flags, size) */
    size_t sz = (size_t)drwrap_get_arg(wrapcxt, IF_WINDOWS_ELSE(2, 0));
    DRCCTLIB_PRINTF("pre_malloc size %d", sz);

    // /* find the maximum malloc request */
    // if (sz > max_malloc) {
    //     dr_mutex_lock(max_lock);
    //     if (sz > max_malloc)
    //         max_malloc = sz;
    //     dr_mutex_unlock(max_lock);
    // }
    *user_data = (void *)sz;
    original_allocation_size = sz;
    drwrap_set_arg(wrapcxt, 1, (void *)(sz + 1));
}

static void
post_malloc(void *wrapcxt, void *user_data)
{
    DRCCTLIB_PRINTF("post_malloc");

    // uintptr_t retaddr = (uintptr_t)drwrap_get_retaddr(wrapcxt);
    app_pc malloc_addr = (app_pc)drwrap_get_retval(wrapcxt);

    DRCCTLIB_PRINTF("post_malloc malloc_addr %d", malloc_addr);
    DRCCTLIB_PRINTF("post_malloc original_allocation_size %d", original_allocation_size);

    app_pc red_zone_addr = malloc_addr + original_allocation_size;

    DRCCTLIB_PRINTF("post_malloc red_zone_addr %d", red_zone_addr);

    void *drcontext = dr_get_current_drcontext();
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, 0);

    red_map_item rm;
    rm.ctxt_hndl = cur_ctxt_hndl;
    rm.malloc_addr = malloc_addr;
    redmap.insert(std::pair<app_pc, red_map_item>(red_zone_addr, rm));
    // redmap[red_zone_addr] = cur_ctxt_hndl;

    // #ifdef SHOW_RESULTS /* we want determinism in our test suite */
    //     size_t sz = (size_t)user_data;
    //     /* test out-of-memory by having a random moderately-large alloc fail */
    //     if (sz > 1024 && dr_get_random_value(1000) < 10) {
    //         bool ok = drwrap_set_retval(wrapcxt, NULL);
    //         DR_ASSERT(ok);
    //         dr_mutex_lock(max_lock);
    //         malloc_oom++;
    //         dr_mutex_unlock(max_lock);
    //     }
    // #endif
}

static void
pre_free(void *wrapcxt, OUT void **user_data)
{
    DRCCTLIB_PRINTF("pre_free");

    /* free(void *ptr) */
    app_pc free_addr = (app_pc)drwrap_get_arg(wrapcxt, 0);

    std::vector<app_pc> to_remove;
    auto it = redmap.begin();
    while (it != redmap.end()) {
        if (it->second.malloc_addr == free_addr) {
            to_remove.push_back(it->first);
        }
        it++;
    }

    for (auto &it2 : to_remove) {
        redmap.erase(it2);
    }
}

static void
post_free(void *wrapcxt, void *user_data)
{
}

// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, mem_ref_t *ref)
{
    DRCCTLIB_PRINTF("DoWhatClientWantTodo");

    size_t mem_size = ref->size;
    app_pc mem_addr = ref->addr;

    DRCCTLIB_PRINTF("DoWhatClientWantTodo mem_size %d", mem_size);
    DRCCTLIB_PRINTF("DoWhatClientWantTodo mem_addr %d", mem_addr);

    for (size_t i = 0; i < mem_size; i++) {
        DRCCTLIB_PRINTF("DoWhatClientWantTodo i %d", i);

        if (redmap.count(mem_addr + i) > 0) {
            DRCCTLIB_PRINTF("DoWhatClientWantTodo inside if");

            std::map<app_pc, red_map_item>::iterator it;
            it = redmap.find(mem_addr + i);
            int64_t concat_contexts =
                ((int64_t)it->second.ctxt_hndl << 32) | cur_ctxt_hndl;

            heap_overflow.push_back(concat_contexts);
        }
    }
}

// dr clean call
void
InsertCleancall(int32_t slot, int32_t num)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i]);
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr, free_reg;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &free_reg) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, free_reg,
                                    reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                      OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(free_reg)));

    // store mem_ref_t->size
#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(
                drcontext, opnd_create_reg(free_reg),
                OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, size)),
                OPND_CREATE_CCT_INT(drutil_opnd_mem_size_in_bytes(ref, where))));
#endif

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
#endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, free_reg) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
        }
    }
    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 2,
                         OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(num));
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list =
        (mem_ref_t *)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    dr_fprintf(gTraceFile,
               "=========================HEAP OVERFLOWS==========================\n");

    dr_fprintf(gTraceFile,
               "=====================================================================\n");

    DRCCTLIB_PRINTF("ClientExit heap_overflow size %d", heap_overflow.size());

    int count = 0;
    for (uint i = 0; i < heap_overflow.size(); i++) {
        if (count >= TOP_REACH_NUM_SHOW) {
            break;
        }
        dr_fprintf(
            gTraceFile,
            "------------------------Allocation Context-------------------------\n");

        int32_t Ctxt_malloc = (int32_t)(heap_overflow[i] & 0xffffffffUL);
        drcctlib_print_full_cct(gTraceFile, Ctxt_malloc, true, true,
                                MAX_CLIENT_CCT_PRINT_DEPTH);

        dr_fprintf(
            gTraceFile,
            "-------------------------------------------------------------------\n");
        dr_fprintf(
            gTraceFile,
            "------------------------Access Context-----------------------------\n");

        dr_fprintf(gTraceFile, "Access Context:");

        int32_t Ctxt_access = (int32_t)(heap_overflow[i] >> 32);
        drcctlib_print_full_cct(gTraceFile, Ctxt_access, true, true,
                                MAX_CLIENT_CCT_PRINT_DEPTH);

        dr_fprintf(
            gTraceFile,
            "=====================================================================\n");
        count++;
    }

    drcctlib_exit();
    dr_close_file(gTraceFile);

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_drdeadspy dr_raw_tls_calloc fail");
    }
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_drdeadspy failed to "
                        "unregister in ClientExit");
    }
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
    drutil_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_heap_overflow'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "unable to initialize drutil");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_heap_overflow dr_raw_tls_calloc fail");
    }
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback,
                  false);
    drwrap_init();
    drmgr_register_module_load_event(module_load_event);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif