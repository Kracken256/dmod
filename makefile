CC = g++
CXXFLAGS = -Iinclude -lz -O0 -g

SOURCES = $(shell find source -name '*.cpp' -printf '%P\n' -not -name 'dmod-ng.cpp')
OBJDIR = obj
BUILD_DIR = build
OBJECTS =  $(addprefix $(OBJDIR)/, $(SOURCES:.cpp=.obj))

all: $(BUILD_DIR)/dmod $(BUILD_DIR)/libdmod.a

$(BUILD_DIR)/libdmod.a: $(OBJECTS)
	@mkdir -p $(@D)
	@echo "Making library $@"
	@ar rcs $@ $^

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

.PHONY: all clean