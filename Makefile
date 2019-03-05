export V?=1

.PHONY: all
all: ca ta tools_dump tools_afl_validate

.PHONY: ca
ca:
	@echo Building CA...
	@mkdir -p shared
	@touch shared/_.o
	@-rm shared/*.o
	$(MAKE) -C ca CROSS_COMPILE="$(CROSS_COMPILE_NS_USER)" TEEC_EXPORT="$(TEEC_EXPORT)"

.PHONY: ta
ta:
	@echo Building TA...
	@mkdir -p shared
	@touch shared/_.o
	@-rm shared/*.o
	$(MAKE) -C ta CROSS_COMPILE="$(CROSS_COMPILE_S_USER)" TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)"

out:
	mkdir out

shared: shared/info.c shared/validate.c shared/include/afl-tee.h shared/include/info.h

tools_dump: out shared tools/dump.c
	$(CC) -O3 -g -o out/tee_svc_dump -I shared/include -I ../optee_os/lib/libutee/include tools/dump.c shared/info.c shared/validate.c

tools_afl_validate: out shared tools/afl_validate.so.c
	$(CC) -shared -O3 -fPIC -o out/afl_validate.so -I shared/include -I ../optee_os/lib/libutee/include tools/afl_validate.so.c shared/info.c shared/validate.c

clean:
	rm -rf out
	rm -rf shared/*.o
	rm -rf ca/*.o