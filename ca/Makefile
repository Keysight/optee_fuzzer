CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

INVOKE_OBJS = main.o rt.o ../shared/validate.o ../shared/info.o

CFLAGS += -g -Wall -I../shared/include -I../ta/include -I$(TEEC_EXPORT)/include -I../../optee_os/lib/libutee/include -I./include

#Add/link other required libraries here
LDADD += -lteec -L$(TEEC_EXPORT)/lib

.PHONY: all
all: tee_invoke_svc

tee_invoke_svc: $(INVOKE_OBJS)
	$(CC) -o $@ $(INVOKE_OBJS) $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)
