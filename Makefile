TARGET=firebase-rest-api
ENTRY_POINT=$(SRC_DIR)/main.c

VERSION ?= .1.0
DEBUG ?= 1
OPTIMIZE ?= -O2
USE_REGULAR_EXPRESSION ?= 1

CC=gcc -std=gnu99 -D_GNU_SOURCE
LINKER=gcc -std=gnu99 -D_GNU_SOURCE
AR=ar crf

CFLAGS=-Wall -Iinclude -Iutils
LDFLAGS=
LIBS=-lm -lpthread -ljson-c -lcurl

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG
OPTIMIZE=-O0
endif

ifeq ($(USE_REGULAR_EXPRESSION),1)
LIBS += -lpcre
endif

LDFLAGS += $(OPTIMIZE)

BIN_DIR=bin
LIB_DIR=lib

# ./src
SRC_DIR=src
OBJ_DIR=obj

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SOURCES_SHARED := $(filter-out $(ENTRY_POINT),$(SOURCES))
OBJECTS_SHARED :=$(SOURCES_SHARED:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o.shared)

# ./utils
UTILS_SRC_DIR=utils
UTILS_OBJ_DIR=obj/utils

UTILS_SOURCES := $(wildcard $(UTILS_SRC_DIR)/*.c)
UTILS_OBJECTS := $(UTILS_SOURCES:$(UTILS_SRC_DIR)/%.c=$(UTILS_OBJ_DIR)/%.o)
UTILS_SOURCES_SHARED := $(UTILS_SOURCES)
UTILS_OBJECTS_SHARED := $(UTILS_SOURCES_SHARED:$(UTILS_SRC_DIR)/%.c=$(UTILS_OBJ_DIR)/%.o.shared)

all: do_init $(BIN_DIR)/$(TARGET) $(LIB_DIR)/$(TARGET).so

# build CLI-runtime 
$(BIN_DIR)/$(TARGET): $(OBJECTS) $(UTILS_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJECTS) : $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -o $@ $(CFLAGS)  -c $<

$(UTILS_OBJECTS) : $(UTILS_OBJ_DIR)/%.o : $(UTILS_SRC_DIR)/%.c
	$(CC) -o $@ $(CFLAGS)  -c $<
	
# build dlls
$(LIB_DIR)/$(TARGET).so: $(LIB_DIR)/$(TARGET).so$(VERSION)
	@ if [ -e "$(LIB_DIR)/$(TARGET).so" ]; then rm "$(LIB_DIR)/$(TARGET).so"; fi
	@ cd $(LIB_DIR); ln -s "$(TARGET).so$(VERSION)" "$(TARGET).so"
	
$(LIB_DIR)/$(TARGET).so$(VERSION): $(OBJECTS_SHARED) $(UTILS_OBJECTS_SHARED)
	$(CC) $(LDFLAGS) -fPIC -shared -o $@ $^ $(LIBS)

$(OBJECTS_SHARED) : $(OBJ_DIR)/%.o.shared : $(SRC_DIR)/%.c
	$(CC) -fPIC -o $@ $(CFLAGS)  -c $<
		
$(UTILS_OBJECTS_SHARED) : $(UTILS_OBJ_DIR)/%.o.shared : $(UTILS_SRC_DIR)/%.c
	$(CC) -fPIC -o $@ $(CFLAGS) -c $<
	
.PHONY: do_init clean
do_init:
	@echo "== stage::do_init"
	mkdir -p $(OBJ_DIR) $(UTILS_OBJ_DIR) $(BIN_DIR) $(LIB_DIR)

clean:
	@echo "== stage::clean"
	rm -f $(OBJ_DIR)/*.o $(OBJ_DIR)/*.shared $(UTILS_OBJ_DIR)/*.o $(UTILS_OBJ_DIR)/*.o.shared $(LIB_DIR)/$(TARGET).so*
