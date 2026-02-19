# 编译器设置
CC = gcc
CXX = g++
CFLAGS = -Wall -O2
CXXFLAGS = -Wall -O2
TARGET = paper

# 自动查找所有 .c 和 .cpp 文件
C_SOURCES = $(wildcard *.c)
CXX_SOURCES = $(wildcard *.cpp)
C_OBJECTS = $(C_SOURCES:.c=.o)
CXX_OBJECTS = $(CXX_SOURCES:.cpp=.o)

# 链接所有目标文件生成可执行文件
$(TARGET): $(C_OBJECTS) $(CXX_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

# 编译 .c 文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 编译 .cpp 文件
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 清理编译产物
clean:
	rm -f $(TARGET) *.o
