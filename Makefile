CFLAGS ?= -g -O3
CFLAGS += -Wall -Wno-format-truncation

CFLAGS += -I"$(ERTS_INCLUDE_DIR)"
CFLAGS += -Ic_src

PRIV_DIR = $(MIX_APP_PATH)/priv
LIB_NAME = $(PRIV_DIR)/bcrypt_nif.so
ifneq ($(CROSSCOMPILE),)
    # crosscompiling
    CFLAGS += -fPIC
else
    # not crosscompiling
    ifneq ($(OS),Windows_NT)
        CFLAGS += -fPIC

        ifeq ($(shell uname),Darwin)
            LDFLAGS += -dynamiclib -undefined dynamic_lookup
        endif
    endif
endif

NIF_SRC=\
	c_src/bcrypt_nif.c\
	c_src/blowfish.c

calling_from_make:
	mix compile

all: $(PRIV_DIR) $(LIB_NAME)

$(LIB_NAME): $(NIF_SRC)
	$(CC) $(CFLAGS) -shared $(LDFLAGS) $^ -o $@

$(PRIV_DIR):
	mkdir -p $@

clean:
	rm -f $(LIB_NAME)

.PHONY: all clean
