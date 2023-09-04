CC = g++
CXXFLAGS = -Iinclude -lz -std=c++20 -shared

SOURCES = $(shell find source -name '*.cpp' -printf '%P\n' -not -name 'dmod-ng.cpp')
OBJDIR = obj
BUILD_DIR = build
OBJECTS =  $(addprefix $(OBJDIR)/, $(SOURCES:.cpp=.obj))

all: $(BUILD_DIR)/dmod $(BUILD_DIR)/libdmod.so

$(BUILD_DIR)/libdmod.so: $(OBJECTS)
	@mkdir -p $(@D)
	@echo "Making library $@"
	@$(CC) -o $@ $(OBJECTS) $(CXXFLAGS) -s -lcrypto -lc -static-libgcc -static-libstdc++

$(BUILD_DIR)/dmod: $(BUILD_DIR)/libdmod.a dmod-ng.cpp
	@mkdir -p $(@D)
	@echo "Building tool $@"
	@$(CC) dmod-ng.cpp build/libdmod.a -o $@ $(CXXFLAGS) -s -lcrypto -lc -static-libgcc -static-libstdc++

$(OBJDIR)/%.obj: source/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) -c -o $@ $< $(CXXFLAGS) 

clean:
	@rm -rf $(OBJDIR) $(BUILD_DIR)

install:
	cp $(BUILD_DIR)/libdmod.so /usr/lib
	cp include/dmod.h /usr/local/include
	cp $(BUILD_DIR)/dmod /usr/local/bin
	@echo "Installed dmod-ng"

.PHONY: all clean install