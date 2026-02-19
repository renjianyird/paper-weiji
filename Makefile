# 编译器设置
CC = gcc
CXX = g++
CFLAGS = -Wall -O2 -I./include
CXXFLAGS = -Wall -O2 -I./include
TARGET = paper

# 源文件目录
SRC_DIR = src

# 自动查找 src/ 目录下所有 .c 和 .cpp 文件
C_SOURCES = $(wildcard $(SRC_DIR)/*.c)
CXX_SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
C_OBJECTS = $(C_SOURCES:.c=.o)
CXX_OBJECTS = $(CXX_SOURCES:.cpp=.o)

# 链接所有目标文件生成可执行文件，链接所有必要的 Windows 库
$(TARGET): $(C_OBJECTS) $(CXX_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lpcap -lws2_32 -lwininet

# 编译 .c 文件
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 编译 .cpp 文件
$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 清理编译产物
clean:
	rm -f $(TARGET) $(SRC_DIR)/*.o
