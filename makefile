KERNEL_MODULE := mfw_kmod
CLI_BINARY := mfw

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

BUILD_DIR := build

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2

.PHONY: all
all: $(BUILD_DIR)/$(KERNEL_MODULE).ko $(BUILD_DIR)/$(CLI_BINARY)


$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)


$(BUILD_DIR)/$(KERNEL_MODULE).ko: $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules
	cp kernel/$(KERNEL_MODULE).ko $(BUILD_DIR)/


$(BUILD_DIR)/$(CLI_BINARY): user/main.cpp include/mfw_protocol.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) \
		-Iinclude \
		-o $(BUILD_DIR)/$(CLI_BINARY) \
		user/main.cpp


.PHONY: kernel
kernel:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules


.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
	rm -rf $(BUILD_DIR)


.PHONY: install
install: all
	install -m 755 $(BUILD_DIR)/$(CLI_BINARY) /usr/local/bin/$(CLI_BINARY)
	insmod $(BUILD_DIR)/$(KERNEL_MODULE).ko


.PHONY: uninstall
uninstall:
	-rmmod $(KERNEL_MODULE)
	rm -f /usr/local/bin/$(CLI_BINARY)
