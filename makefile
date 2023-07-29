CC = g++
CXXFLAGS = -Isrc -O3 -lcrypto -lssl -lz -s

SOURCES = $(shell find src -name '*.cpp' -printf '%P\n')
OBJDIR = obj
BUILD_DIR = build
OBJECTS =  $(addprefix $(OBJDIR)/, $(SOURCES:.cpp=.o))

all: $(BUILD_DIR)/dmod

$(BUILD_DIR)/dmod: $(OBJECTS)
	@mkdir -p $(@D)
	@echo "Linking $^"
	@$(CC) -o $@ $^  $(CXXFLAGS) 

$(OBJDIR)/%.o: src/%.cpp
	@mkdir -p $(@D)
	@echo "Compiling $<"
	@$(CC) -c -o $@ $< $(CXXFLAGS) 

clean:
	@rm -rf $(OBJDIR) $(BUILD_DIR)

.PHONY: all clean