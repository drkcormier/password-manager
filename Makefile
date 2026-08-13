CXX = g++
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra
TARGET = pwvault
SRC = src/main.cpp

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) src/aes.hpp src/kdf.hpp src/sha256.hpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET)
