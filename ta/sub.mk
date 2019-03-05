global-incdirs-y += include ../shared/include

srcs-y += main.c svc.c ../shared/info.c ../shared/validate.c

cflags-y += -DTA_BUILD -DCFG_AFL_ENABLE -funwind-tables
cflags-y += -Wno-pedantic -Wno-declaration-after-statement -Wno-switch-default
cflags-y += -Wno-unused-parameter -Wno-missing-prototypes -Wno-missing-declarations
cflags-y += -Wno-discarded-qualifiers -Wno-pointer-to-int-cast -Wno-switch -Wno-format -Wno-format-nonliteral -Wno-format-security
cflags-y += -Wno-unused-function -Wno-error=unused-variable -Wno-error=shadow
