# rdelf
analyse ELF file.print part of the Header of a 32-bit/64-bit ELF file and map sections to corresponding segments.
һ��ELF�ļ�����������ӡ�������ļ�ͷ��Ϣ������ʹ�ӡ��section��segment��ӳ���ϵ��

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
