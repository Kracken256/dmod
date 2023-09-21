CC = g++
CXXFLAGS = -Iinclude -l:libz.a -std=c++20

SOURCES = $(shell find source -name '*.cpp' -printf '%P\n' -not -name 'dmod-ng.cpp')
OBJDIR = obj
BUILD_DIR = build
OBJECTS =  $(addprefix $(OBJDIR)/, $(SOURCES:.cpp=.obj))

all: $(BUILD_DIR)/dmod $(BUILD_DIR)/libdmod.a

$(BUILD_DIR)/libdmod.a: $(OBJECTS)
	@mkdir -p $(@D)
	@echo "Making library $@"
	cd $(OBJDIR) && ar x /usr/lib/x86_64-linux-gnu/libz.a
	cd $(OBJDIR) && ar -qc libdmod.a *.obj *.o
	mv $(OBJDIR)/libdmod.a $(BUILD_DIR)/libdmod.a

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
	cp $(BUILD_DIR)/libdmod.a /usr/lib
	cp include/dmod.h /usr/local/include
	cp $(BUILD_DIR)/dmod /usr/local/bin
	@echo "Installed dmod-ng"

.PHONY: all clean install
