# rdelf
analyse ELF file.print part of the Header of a 32-bit/64-bit ELF file and map sections to corresponding segments.
一个ELF文件分析器，打印出部分文件头信息，计算和打印出section和segment的映射关系。

# needed
gcc
g++ (>=4.8)
cmake (>=2.6)
make

# compile
$ mkdir build && cd build
$ cmake ..
$ make

# usage
$ ./bin/rdelf ./elf_test_file
