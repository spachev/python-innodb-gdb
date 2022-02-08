#! /usr/bin/python

import gdb
import string
from goto import with_goto

UT_HASH_RANDOM_MASK2=0x62946a4f
LOCK_REC = 0x20
UNIV_PAGE_SIZE = 16384
ULINT_UNDEFINED = (1 << 65) - 1
ULINT32_UNDEFINED = (1 << 32) - 1
UNIV_SQL_NULL = ULINT32_UNDEFINED
REC_OFFS_HEADER_SIZE = 2
OFFS_IN_REC_NORMAL_SIZE = 100
REC_OFFS_NORMAL_SIZE = OFFS_IN_REC_NORMAL_SIZE
DICT_TF_COMPACT              =  1
DATA_NOT_NULL  =    256

DICT_CLUSTERED = 1       #!< clustered index; for other than
#                                auto-generated clustered indexes,
#                                also DICT_UNIQUE will be set
DICT_UNIQUE = 2       #!< unique index
DICT_IBUF = 8       #!< insert buffer tree
DICT_CORRUPT = 16      #!< bit to store the corrupted flag
#                                in SYS_INDEXES.TYPE
DICT_FTS = 32      # FTS index; can't be combined with the
#                                other flags
DICT_SPATIAL = 64      # SPATIAL index; can't be combined with the
#                                other flags
DICT_VIRTUAL = 128     # Index on Virtual column
#
DICT_IT_BITS = 8       #!< number of bits used for
#                                SYS_INDEXES.TYPE


#* Number of extra bytes in an old-style record,
#in addition to the data and the offsets
REC_N_OLD_EXTRA_BYTES = 6
## Number of extra bytes in a new-style record,
#in addition to the data and the offsets
REC_N_NEW_EXTRA_BYTES = 5
#
## Record status values
REC_STATUS_ORDINARY = 0
REC_STATUS_NODE_PTR = 1
REC_STATUS_INFIMUM = 2
REC_STATUS_SUPREMUM = 3

FIL_PAGE_DATA = 38
FSEG_PAGE_DATA = FIL_PAGE_DATA
PAGE_HEADER = FSEG_PAGE_DATA
PAGE_N_DIR_SLOTS = 0      # number of slots in page directory
PAGE_HEAP_TOP = 2      # pointer to record heap top
PAGE_N_HEAP = 4      # number of records in the heap,
                        #       bit = 15=flag: new-style compact page format
PAGE_FREE = 6      # pointer to start of page free record list
PAGE_GARBAGE = 8      # number of bytes in deleted records
PAGE_LAST_INSERT = 10     # pointer to the last inserted record, or
                        #       NULL if this info has been reset by a delete,
                        #       for example
PAGE_DIRECTION = 12     # last insert direction: PAGE_LEFT, ...
PAGE_N_DIRECTION = 14     # number of consecutive inserts to the same
                        #       direction
PAGE_N_RECS = 16     # number of user records on the page
PAGE_MAX_TRX_ID = 18     # highest id of a trx which may have modified
                        #       a record on the page; trx_id_t; defined only
                        #       in secondary indexes and in the insert buffer
                        #       tree
PAGE_HEADER_PRIV_END = 26 # end of private data structure of the page
                        #       header which are set in a page create
PAGE_LEVEL = 26     # level of the node in an index tree; the
                        #       leaf level is the level = 0.  This field should
                        #       not be written to after page creation.
PAGE_INDEX_ID = 28     # index id where the page belongs.
                        #       This field should not be written to after
                        #       page creation.
PAGE_BTR_SEG_LEAF = 36    # file segment header for the leaf pages in
                        #       a B-tree: defined only on the root page of a
                        #       B-tree, but not in the root of an ibuf tree

FSEG_HEADER_SIZE  = 10
PAGE_HEAP_NO_SUPREMUM   =     1

PAGE_DATA       = (PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE)
                            # start of data on the page

PAGE_OLD_INFIMUM        = (PAGE_DATA + 1 + REC_N_OLD_EXTRA_BYTES)
                            # offset of the page infimum record on an
                            # old-style page
PAGE_OLD_SUPREMUM       = (PAGE_DATA + 2 + 2 * REC_N_OLD_EXTRA_BYTES + 8)
                            # offset of the page supremum record on an
                            # old-style page
PAGE_OLD_SUPREMUM_END = (PAGE_OLD_SUPREMUM + 9)
                            # offset of the page supremum record end on
                            # an old-style page
PAGE_NEW_INFIMUM        = (PAGE_DATA + REC_N_NEW_EXTRA_BYTES)
                            # offset of the page infimum record on a
                            # new-style compact page
PAGE_NEW_SUPREMUM       = (PAGE_DATA + 2 * REC_N_NEW_EXTRA_BYTES + 8)
                            # offset of the page supremum record on a
                            # new-style compact page
PAGE_NEW_SUPREMUM_END = (PAGE_NEW_SUPREMUM + 8)
                            # offset of the page supremum record end on
                            # a new-style compact page


## Compact flag ORed to the extra size returned by rec_get_offsets()
REC_OFFS_COMPACT = (1 << 31)
## SQL NULL flag in offsets returned by rec_get_offsets()
REC_OFFS_SQL_NULL = (1 << 31)
## External flag in offsets returned by rec_get_offsets()
REC_OFFS_EXTERNAL = (1 << 30)
## Mask for offsets returned by rec_get_offsets()
REC_OFFS_MASK = (REC_OFFS_EXTERNAL - 1)


REC_NEXT = 2
REC_NEXT_MASK = 0xFFFF
REC_NEXT_SHIFT = 0
#
REC_OLD_SHORT = 3       # This is single byte bit-field
REC_OLD_SHORT_MASK = 0x1
REC_OLD_SHORT_SHIFT = 0
#
REC_OLD_N_FIELDS = 4
REC_OLD_N_FIELDS_MASK = 0x7FE
REC_OLD_N_FIELDS_SHIFT = 1
#
REC_NEW_STATUS = 3       # This is single byte bit-field
REC_NEW_STATUS_MASK = 0x7
REC_NEW_STATUS_SHIFT = 0
#
REC_OLD_HEAP_NO = 5
REC_HEAP_NO_MASK = 0xFFF8
REC_NEW_HEAP_NO = 4
REC_HEAP_NO_SHIFT = 3
#
REC_OLD_N_OWNED = 6       # This is single byte bit-field
REC_NEW_N_OWNED = 5       # This is single byte bit-field
REC_N_OWNED_MASK = 0xF
REC_N_OWNED_SHIFT = 0
#
REC_OLD_INFO_BITS = 6       # This is single byte bit-field
REC_NEW_INFO_BITS = 5       # This is single byte bit-field
REC_INFO_BITS_MASK = 0xF
REC_INFO_BITS_SHIFT = 0
DATA_BLOB = 5
DATA_GEOMETRY = 14

def DATA_LARGE_MTYPE(mtype):
    return mtype == DATA_BLOB or mtype == DATA_GEOMETRY

def DATA_BIG_LEN_MTYPE(len, mtype):
    return len > 255 or DATA_LARGE_MTYPE(mtype)

def DATA_BIG_COL(col):
    return DATA_BIG_LEN_MTYPE(col['len'], col['mtype'])

def mach_read_from_2(b):
    return int(b[0]) << 8 | int(b[1])

def mach_read_from_1(b):
    return int(b[0])

def rec_get_bit_field_2(rec,offs,mask,shift):
    return ((mach_read_from_2(rec - offs) & mask) >> shift)


def rec_offs_set_n_fields(offsets,n_fields):
    offsets[1] = n_fields


def page_is_comp(page):
    return int(page[PAGE_HEADER + PAGE_N_HEAP]) & 0x80

def rec_get_heap_no_old(rec):
    return rec_get_bit_field_2(rec, REC_OLD_HEAP_NO,
                                   REC_HEAP_NO_MASK, REC_HEAP_NO_SHIFT)

def rec_get_heap_no_new(rec):
    return rec_get_bit_field_2(rec, REC_NEW_HEAP_NO,
                                   REC_HEAP_NO_MASK, REC_HEAP_NO_SHIFT)

def ut_align_offset(ptr, align_no):
    return ptr_to_ulint(ptr) & (align_no - 1)


def rec_get_next_offs(rec,comp):

    field_value = mach_read_from_2(rec - REC_NEXT)

    if (comp):
        if field_value == 0:
            return 0


    return ut_align_offset(rec + field_value, UNIV_PAGE_SIZE)

def rec_offs_comp(offsets):
    return offsets[REC_OFFS_HEADER_SIZE] & REC_OFFS_COMPACT

def rec_get_info_bits(rec, comp):
        return  rec_get_bit_field_1(
                rec, REC_NEW_INFO_BITS if comp else REC_OLD_INFO_BITS,
                REC_INFO_BITS_MASK, REC_INFO_BITS_SHIFT)

def ut_buf_to_str(buf, buf_len):
    buf = buf.cast(gdb.lookup_type("unsigned char").pointer())
    buf_end = buf + buf_len
    p = buf
    s = "hex: "
    while p < buf_end:
        s += "%02x" % int(p[0])
        p += 1
    s += " asc: "
    p = buf
    while p < buf_end:
        val = int(p[0])
        if val >= 32 and val < 128:
            s += str(unichr(val))
        else:
            s +=  ' '
        p += 1
    return s

def rec_get_nth_field(rec, offsets, n):
    pos, len = rec_get_nth_field_offs(offsets, n)
    return rec + pos, len

def rec_get_nth_field_offs(offsets, n):
    if n == 0:
        offs = 0
    else:
        offs = offsets[REC_OFFS_HEADER_SIZE + n] & REC_OFFS_MASK

    length = offsets[REC_OFFS_HEADER_SIZE + 1 + n];

    if length & REC_OFFS_SQL_NULL:
        length = UNIV_SQL_NULL
    else:
        length &= REC_OFFS_MASK
        length -= offs

    return offs,length


def rec_comp_to_str(rec, offsets):
    res = ""

    for i in range(0,rec_offs_n_fields(offsets)):
        data,len = rec_get_nth_field(rec, offsets, i)
        res += "{}: ".format(i)
        if len != UNIV_SQL_NULL:
            if (len <= 30):
                res += ut_buf_to_str(data, len)
            elif rec_offs_nth_extern(offsets, i):
                res += ut_but_to_str(data, 30)
                res += "(total {} bytes, external)".format(len)
                res += ut_buf_to_str(data + len
                                            - BTR_EXTERN_FIELD_REF_SIZE,
                                            BTR_EXTERN_FIELD_REF_SIZE)
            else:
                 res += ut_buf_to_str(data, 30)
                 res += '(total {} bytes)'.format(len)

        else:
            res += " SQL NULL"
        res += ";\n"
    return res


def rec_to_str(rec, offsets):
    if not rec_offs_comp(offsets):
        return "TODO: implement old format"

    res =  (("PHYSICAL RECORD: n_fields {};" +
            " compact format; info bits {}\n").format(
            rec_offs_n_fields(offsets),
            rec_get_info_bits(rec, True)))

    res += rec_comp_to_str(rec, offsets)
    return res


def rec_get_bit_field_1(rec, offs, mask, shift):
    return (mach_read_from_1(rec - offs) & mask) >> shift


def rec_get_status(rec):
    return rec_get_bit_field_1(rec, REC_NEW_STATUS,
                                  REC_NEW_STATUS_MASK, REC_NEW_STATUS_SHIFT)

def rec_offs_set_n_alloc(offsets, n_alloc):
    offsets[0] = n_alloc

def ptr_to_ulint(ptr):
    return int(ptr.cast(gdb.lookup_type("unsigned long long")))

def rec_offs_make_valid(rec,index,offsets):
    offsets[2] = ptr_to_ulint(rec)
    offsets[3] = ptr_to_ulint(index)

def dict_table_is_comp(table):
    return table['flags'] & DICT_TF_COMPACT

def dict_index_is_clust(index):
        return index['type'] & DICT_CLUSTERED

def dict_index_get_n_fields(index):
    return index['n_fields']

def dict_index_get_n_unique(index):
    return index['n_uniq']

def dict_index_get_n_unique_in_tree(index):
    if dict_index_is_clust(index):
        return dict_index_get_n_unique(index)

    return dict_index_get_n_fields(index)

def dict_index_get_n_unique_in_tree_nonleaf(index):
    if dict_index_is_spatial(index):
        return DICT_INDEX_SPATIAL_NODEPTR_SIZE
    else:
        return dict_index_get_n_unique_in_tree(index)

def rec_offs_n_fields(offsets):
    return offsets[1];

@with_goto
def rec_init_offsets_comp_ordinary(rec, temp, index, offsets):
    i = 0
    offs = 0
    any_ext = 0
    n_null = index['n_nullable']
    nulls   =  rec - 1 if temp else rec - (1 + REC_N_NEW_EXTRA_BYTES)
    lens = nulls - UT_BITS_IN_BYTES(n_null)
    null_mask   = 1

    if (temp and dict_table_is_comp(index['table'])):
        temp = False

    while True:
        field  = dict_index_get_nth_field(index, i)
        col = dict_field_get_col(field)

        if not (col['prtype'] & DATA_NOT_NULL):

            if not  null_mask:
                nulls -= 1
                null_mask = 1



            if (nulls.dereference() & null_mask):
                null_mask <<= 1
                len = offs | REC_OFFS_SQL_NULL;
                goto .resolved
            null_mask <<= 1;

        if (not field['fixed_len'] or (temp and not dict_col_get_fixed_size(col, temp))):
            len = lens.dereference()
            lens -= 1
            if (DATA_BIG_COL(col)):
                if (len & 0x80):
                    len <<= 8;
                    len |= lens.dereference()
                    lens -= 1
                    offs += len & 0x3fff;
                if (len & 0x4000):
                    any_ext = REC_OFFS_EXTERNAL
                    len = offs | REC_OFFS_EXTERNAL
                else:
                    len = offs
                goto .resolved

            offs += len
            len = offs
        else:
            offs += field['fixed_len']
            len = offs
        label .resolved
        offsets[REC_OFFS_HEADER_SIZE + i + 1] = int(len)
        i += 1
        if not (i < rec_offs_n_fields(offsets)):
            break

    offsets[REC_OFFS_HEADER_SIZE] = int((rec - (lens + 1)) | REC_OFFS_COMPACT | any_ext)


def dict_field_get_col(field):
    return field['col']

def dict_index_get_nth_field(index, pos):
    return index['fields'] + pos

def UT_BITS_IN_BYTES(b):
    return (int(b) + 7) // 8

@with_goto
def rec_init_offsets(rec, index, offsets):
    i= 0
    rec_offs_make_valid(rec, index, offsets)

    if (dict_table_is_comp(index['table'])):
        status = rec_get_status(rec)
        n_node_ptr_field = ULINT_UNDEFINED

        if status == REC_STATUS_INFIMUM:
            offsets[REC_OFFS_HEADER_SIZE] = REC_N_NEW_EXTRA_BYTES | REC_OFFS_COMPACT;
            offsets[REC_OFFS_HEADER_SIZE + 1] = 8
            return
        elif status == REC_STATUS_NODE_PTR:
            n_node_ptr_field = dict_index_get_n_unique_in_tree_nonleaf(index)
        elif status == REC_STATUS_ORDINARY:
            rec_init_offsets_comp_ordinary(rec, False, index, offsets)
            return;

        nulls = rec - (REC_N_NEW_EXTRA_BYTES + 1)
        lens = nulls - UT_BITS_IN_BYTES(index["n_nullable"])
        offs = 0
        null_mask = 1

        while True:
            if i == n_node_ptr_field:
                offs += REC_NODE_PTR_SIZE
                len = offs
                goto .resolved

            field = dict_index_get_nth_field(index, i)
            if not (dict_field_get_col(field)['prtype'] & DATA_NOT_NULL):

                if not null_mask:
                    nulls -= 1
                    null_mask = 1

                if nulls.dereference() & null_mask:
                    null_mask <<= 1
                    len = offs | REC_OFFS_SQL_NULL
                    goto .resolved
                null_mask <<= 1;

            if not field['fixed_len']:
                col = dict_field_get_col(field);
                len = lens.dereference()
                lens -= 1
                if DATA_BIG_COL(col):
                    if len & 0x80:
                        len <<= 8;
                        len |= lens.dereference()
                        lens -= 1
                        offs += len & 0x3fff;
                        len = offs;
                        goto .resolved;
                offs += len
                len = offs
            else:
                offs += field['fixed_len']
                len = offs
            label .resolved
            offsets[i + 1 + REC_OFFS_HEADER_SIZE] = int(len)
            i += 1
            if not (i < rec_offs_n_fields(offsets)):
                break

        offsets[REC_OFFS_HEADER_SIZE] = int(rec - (lens + 1)) | REC_OFFS_COMPACT
    else:
        raise Exception("TODO: implement for the old record format")

def rec_get_offsets(rec,index,offsets,n_fields):
    if dict_table_is_comp(index['table']):
        status = rec_get_status(rec)
        if status == REC_STATUS_ORDINARY:
            n = dict_index_get_n_fields(index);
        elif status == REC_STATUS_NODE_PTR:
            n = dict_index_get_n_unique_in_tree_nonleaf(index) + 1;
        elif status == REC_STATUS_INFIMUM or status == REC_STATUS_SUPREMUM:
            n = 1;
        else:
            return None
    else:
        raise Exception("TODO: implement old dict table format")

    n = min(int(n), int(n_fields))
    size = n + (1 + REC_OFFS_HEADER_SIZE)
    offsets = [0 for _ in range(0,size)]
    rec_offs_set_n_alloc(offsets, size)
    rec_offs_set_n_fields(offsets, n)
    rec_init_offsets(rec, index, offsets)
    return offsets





def page_find_rec_with_heap_no(page, heap_no):
    if page_is_comp(page):
        rec = page + PAGE_NEW_INFIMUM
        while True:
             rec_heap_no = rec_get_heap_no_new(rec)
             if rec_heap_no == heap_no:
                return rec
             elif rec_heap_no == PAGE_HEAP_NO_SUPREMUM :

                                return None

             rec = page + rec_get_next_offs(rec, True);
    else:
        rec = page + PAGE_OLD_INFIMUM

        while True:
            rec_heap_no = rec_get_heap_no_old(rec)
            if rec_heap_no == heap_no:
                return rec
            elif rec_heap_no == PAGE_HEAP_NO_SUPREMUM:
                return None
            rec = page + rec_get_next_offs(rec, False);




def buf_pool_get(space_id, page_no):
    page_id = fold(space_id, page_no)
    f = gdb.selected_frame()
    buf_pool_ptr = f.read_var("buf_pool_ptr")
    srv_buf_pool_instances = f.read_var("srv_buf_pool_instances")
    return buf_pool_ptr[page_id % srv_buf_pool_instances]

def buf_hash_page_get(buf_pool, space_id, page_no):
    return hash_search("hash", buf_pool["page_hash"], space_id, page_no, "buf_page_t",
                       lambda data:  data["id"]["m_space"] == space_id and data["id"]["m_page_no"] == page_no)

def buf_page_get_block(bpage):
    return bpage.cast(gdb.lookup_type("buf_block_t").pointer())

def buf_block_get_frame(block):
    return block["frame"]

def buf_page_try_get(space_id, page_no):
    buf_pool = buf_pool_get(space_id, page_no)
    bpage = buf_hash_page_get(buf_pool, space_id, page_no)
    return buf_page_get_block(bpage)

def hash_get_nth_cell(table, n):
    return table['array'] + n

def hash_get_first(table, hash_val):
    #print("hash_first={} hash_val={}".format(hash_get_nth_cell(table, hash_val)['node'], hash_val))

    return hash_get_nth_cell(table, hash_val)['node']

def hash_get_next(name, data):
    return data[name]

def hash_search(name, table, space_id, page_no, data_type, test_f):
    data = hash_get_first(table, hash_calc_hash(space_id, page_no, table)).cast(gdb.lookup_type(data_type).pointer())
    while data:
        # print(data.dereference())
        if test_f(data):
            return data
        else:
            data = hash_get_next(name, data)
    return data


def hash_calc_hash(space_id, page_no, table):
    return ut_hash_ulint(fold(space_id, page_no), table['n_cells'])

def ut_hash_ulint(key, table_size):
    key = key ^ UT_HASH_RANDOM_MASK2
    return key % table_size

def fold(space_id, page_no):
    return (space_id << 20) + space_id + page_no


def print_rec_list(rec_list):
    for r in rec_list:
        tmp = r.copy()
        del tmp["rec_info"]
        print(tmp)
        print(r["rec_info"])

def print_trx_locks(trx):
    trx_locks = trx["lock"]["trx_locks"]
    start = trx_locks["start"]
    cur = start

    while cur:
        rec_lock = cur["un_member"]["rec_lock"]
        index = cur["index"]
        table_name = cur["index"]["table"]["name"] if cur["index"] else None
        index_name = cur["index"]["name"] if cur["index"] else None
        type_mode = cur["type_mode"]
        rec_lock_map_addr = cur + 1
        rec_lock_map = rec_lock_map_addr.cast(gdb.lookup_type("char").pointer())
        n_bytes = rec_lock["n_bits"]/8
        block = buf_page_try_get(rec_lock["space"], rec_lock["page_no"])
        frame = buf_block_get_frame(block) if block else None

        rec_info_list = []
        offsets = [0 for _ in range(0,REC_OFFS_NORMAL_SIZE)]
        if type_mode & LOCK_REC:
            for i in range(0,n_bytes):
                mask = 0x1
                for j in range(0,8):
                        if rec_lock_map[i] & mask:
                                heap_no = i*8+j
                                rec_info = {'heap_no': heap_no}
                                if frame:
                                    rec = page_find_rec_with_heap_no(frame, heap_no)
                                    rec_info['rec_ptr'] = rec.cast(gdb.lookup_type("char").pointer())
                                    rec_info['offsets'] = offsets = rec_get_offsets(rec, index, offsets,
                                                                          ULINT_UNDEFINED)
                                    rec_info['rec_info'] = rec_to_str(rec, offsets)
                                rec_info_list.append(rec_info)
                        mask <<= 1
        print("rec_lock={} index={} table={} type_mode={} ".format(rec_lock, index_name,
            table_name, type_mode))
        print_rec_list(rec_info_list)
        cur = cur["trx_locks"]["next"]
