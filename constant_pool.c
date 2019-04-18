#include <string.h>
#include <stdlib.h>

#include "constant_pool.h"
#include "njvm.h"

int njvm_constpool_strcmp(struct njvm_constpool_entry *e, char *str) {
    /* DPF("%s == %s\n", (char *) e->data, str); */
    return e->tag == 1 && strlen(str) == e->size && strcmp(e->data, str) == 0;
}

void njvm_constpool_free(struct njvm_constpool_entry *e) {
    free(e->data);
}

int njvm_constpool_load(struct njvm_class *cls, uint32_t index, uint8_t *data) {
    struct njvm_constpool_entry *e = njvm_constpool_get(cls, index);
    e->tag = data[0];
    uint8_t tag = data[0];
    size_t offset = 1;
    DPF(" [%-2d] CP Tag: %-2d - ", index, tag);
    /* DPF("  Additional size: %d\n", constant_pool_size[tag]); */
    uint32_t data_start = 0;
    e->size = -1;

    if(tag == 1) {
        data_start = 3;
        short str_len = htobe16(*((unsigned short *) (data+offset)));
        offset += constant_pool_size[tag];
        // DPF("  String len = %d\n", str_len);
        DPF("utf8: ");
        for(int j = 0; j < str_len; j++) {
            offset++;
            DPF("%c", data[offset]);
        }
        offset++;
        e->size = offset - data_start;
        e->data = malloc(e->size + 1);
        memcpy(e->data, data + data_start, e->size);
        ((uint8_t *) e->data)[e->size] = '\0';
        /* d += str_len; */
    }
    else if(tag == 10) { // methodref
        // DPF("Parsing methodref\n");
        struct njvm_constpool_methodref *mref = malloc(sizeof(struct njvm_constpool_methodref));
        assert(mref != NULL);
        mref->cls = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        mref->nat = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = mref;
        DPF("MREF: #%d #%d", mref->cls, mref->nat);
    }
    else if(tag == 12) {
        struct njvm_constpool_nameandtype *nat = malloc(sizeof(struct njvm_constpool_nameandtype));
        nat->name = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        nat->type = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = nat;
        DPF("NAT:  #%d #%d", nat->name, nat->type);
    }
    else if(tag == 9) {
        struct njvm_constpool_fieldref *fref = malloc(sizeof(struct njvm_constpool_fieldref));
        fref->cls = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        fref->nat = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = fref;
        DPF("FREF: #%d #%d", fref->cls, fref->nat);
    }
    else if(tag == 7) {
        struct njvm_constpool_classref *clsref = malloc(sizeof(struct njvm_constpool_classref));
        clsref->name = htobe16(*((unsigned short *) (data+offset)));
        offset += 2;
        e->data = clsref;
        DPF("CREF: #%d", clsref->name);
    }
    else {
        offset += constant_pool_size[tag];
    }

    DPF("\n");
    return offset;
}

struct njvm_constpool_entry *njvm_constpool_get(struct njvm_class *cls, uint32_t index) {
    if(index >= cls->constant_pool_count) {
        return NULL;
    }

    return cls->constant_pool + index - 1;
}
