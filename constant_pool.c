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
