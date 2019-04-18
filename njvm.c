#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "njvm.h"
#include "zip/src/zip.h"

extern uint8_t *stack, stack_index;
struct njvm_jre jre;
int i;
struct buffer_t {
    char *data;
    size_t size;
};
struct buffer_t buf = {0};

static size_t on_extract(void *arg, unsigned long long offset, const void *data, size_t size) {
    struct buffer_t *buf = (struct buffer_t *)arg;
    buf->data = realloc(buf->data, buf->size + size + 1);
    assert(NULL != buf->data);
    memcpy(&(buf->data[buf->size]), data, size);
    struct njvm_class *cls = njvm_class_load((void *)data, size);
    cls->jre = &jre;
    jre.clss[i] = cls;
    return size;
}


void run_jar(char *path) {
    struct zip_t *zip = zip_open(path, ZIP_DEFAULT_COMPRESSION_LEVEL, 'r');
    jre.cls_count = zip_total_entries(zip);
    jre.clss = calloc(jre.cls_count, sizeof(struct njvm_class));
    /* DPF("Total count: %d", jre.cls_count); */
    for(int i = 0; i < 24; i++) {
        jre.objects[i] = NULL;
    }
    for(i = 0; i < jre.cls_count; ++i) {
        DPF("Open %d\n", i);
        zip_entry_openbyindex(zip, i);
        zip_entry_extract(zip, on_extract, &buf);
    }
    free(buf.data);
    zip_close(zip);
}

int main(int argc, char **argv) {
    stack = malloc(128);
    stack_index = 0;

    if(argc > 2 && strcmp(argv[1], "jar") == 0) {
        DPF("Running jar: %s\n", argv[2]);
        run_jar(argv[2]);
    }
    else {
        /* struct njvm_jre jre; */
        jre.cls_count = argc - 1;
        jre.clss = calloc(jre.cls_count, sizeof(struct njvm_class));

        for(int i = 0; i < 24; i++) {
            jre.objects[i] = NULL;
        }

        for(int i = 0; i < jre.cls_count; i++) {
            DPF(" --- Loading Class: %s\n", argv[i + 1]);
            FILE *fh = fopen(argv[i + 1], "rb");
            fseek(fh, 0, SEEK_END);
            long size = ftell(fh);
            unsigned char *buf = malloc(size);
            rewind(fh);
            fread(buf, 1, size, fh);
            if(!(buf[0] == 0xCA && buf[1] == 0xFE && buf[2] == 0xBA
                        && buf[3] == 0xBE)) {
                DPF("Invalid class signature\n");
                continue;
            }
            struct njvm_class *cls = njvm_class_load(buf, size);
            cls->jre = &jre;
            jre.clss[i] = cls;

            free(buf);
            fclose(fh);
        }
    }

    for(int i = 0; i < jre.cls_count; i++) {
        struct njvm_method *m = njvm_class_getmethod(jre.clss[i], "main");
        if(m != NULL) {
            njvm_exec_method(0, m);
            break;
        }
    }

    njvm_jre_free(&jre);
    free(stack);
    return 0;
}
