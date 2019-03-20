cmake_minimum_required (VERSION 2.6)
# 指定项目名称，编译后生成的可执行文件不一定是这里的名称
project (rdelf)

# 指定执行文件输出目录
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
# 指定库文件输出目录
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
add_executable(rdelf rdelf.cpp)
# add_executable(elf_test_file_32 elf_test_file.cpp)
add_executable(elf_test_file elf_test_file.cpp)
# set_target_properties(elf_test_file_32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

