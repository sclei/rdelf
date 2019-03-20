#include <iostream>
#include <vector>
#include <map>
#include <iomanip>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <fstream>
#include <elf.h>
#include <errno.h>

#include "rdelf.h"

#define N_MAGIC 16   //魔数的长度 16 bytes
typedef std::vector<std::vector<uint64_t> > MAP_SGM_SEC;

template <typename T>
int __pehdr(T *ehdr);
int pehdr(Elf32_Ehdr *ehdr);//显示32bit obj文件的文件头信息
int pehdr(Elf64_Ehdr *ehdr);//显示64bit obj文件的文件头信息

template <typename T1,typename T2>
void init_sec_headers(std::vector<T1> &shdr,T2 *ehdr,std::fstream &ifs);//读取第n个section header

template <typename T1,typename T2>
void init_pro_headers(std::vector<T1> &phdr,T2 *ehdr,std::fstream &ifs);

template <typename T1,typename T2>
void init_map_sgm_sec(MAP_SGM_SEC &,const std::vector<T1> &,const std::vector<T2> &);

template <typename T1,typename T2>
std::string get_sec_name(T1 strtaboff,T2 offset,std::fstream &ifs); //获取section的名字字符串

template <typename T1,typename T2>
void pshdr(T1 *elf_header,T2 &sec_headers,std::fstream &ifs);//显示section headers

template <typename T>
void pphdr(std::vector<T> &program_headers);

template <typename T1,typename T2>
void pmap_sgm_sec(const MAP_SGM_SEC &map_sgm_sec,const T1 & sec_headers,const T2 & elf_header,std::fstream &ifs);

int main(int a,char**args)
{
    if(a<=1)
    {
        std::cout<<"Usage : \n\t rdelf File"<<std::endl;
        return -1;
    }
    
    char *elf_magic;

    Elf32_Ehdr *elf32_header=NULL;
    Elf64_Ehdr *elf64_header=NULL;
    std::map<uint32_t,std::string> sec_strs; //section 的名称字符串数组
    std::vector<Elf32_Shdr> sec32_headers;//section 32 headers
    std::vector<Elf64_Shdr> sec64_headers;//
    std::vector<Elf32_Phdr> pro32_headers;
    std::vector<Elf64_Phdr> pro64_headers;
    MAP_SGM_SEC map_sgm_sec; //Map of segments and sections
    std::fstream ifs; // open an elf file;
    //读文件
    ifs.open(args[1],std::ios::in|std::ios::binary);

    if(!ifs.is_open())
    {
        std::cout<<"Error "<<strerror(errno)<<",errno "<<errno<<std::endl;
        return -1;
    }
    //读取ELF魔数判断ELF的版本 
    elf_magic = new char[N_MAGIC]; //malloc 1
    ifs.read((char *)elf_magic,N_MAGIC);
    ifs.seekg(0,std::ios::beg);//文件指针回到文件开始，便于一次读取ELF文件头
    if(elf_magic[EI_MAG0]!=ELFMAG0||
            elf_magic[EI_MAG1]!=ELFMAG1||
            elf_magic[EI_MAG2]!=ELFMAG2||
            elf_magic[EI_MAG3]!=ELFMAG3)
    {
        //本文件不是ELF文件
        std::cout<<"error this file is not an elf file,errno -1,exit!"<<std::endl;
        return -1;
    }  

    if(elf_magic[EI_CLASS]==ELFCLASSNONE){
        //elf版本无效
        std::cout<<"error this file is not a standard elf file,errno -2,exit!"<<std::endl;
        return -2;
    }else if(elf_magic[EI_CLASS]==ELFCLASS32){
        //32-bit obj文件
        elf32_header = new Elf32_Ehdr[1];
        ifs.read((char *)elf32_header,sizeof(Elf32_Ehdr));
        pehdr(elf32_header);
        //填充sec_strs数组
        init_sec_headers(sec32_headers,elf32_header,ifs);
        init_pro_headers(pro32_headers,elf32_header,ifs);
        init_map_sgm_sec(map_sgm_sec,pro32_headers,sec32_headers);
        pshdr(elf32_header,sec32_headers,ifs);
        pphdr(pro32_headers);
        pmap_sgm_sec(map_sgm_sec,sec64_headers,elf64_header,ifs);
    }else if(elf_magic[EI_CLASS]==ELFCLASS64){
        //64-bit obj文件
        elf64_header = new Elf64_Ehdr[1];
        ifs.read((char*)elf64_header,sizeof(Elf64_Ehdr));
        pehdr(elf64_header);
        init_sec_headers(sec64_headers,elf64_header,ifs);
        init_pro_headers(pro64_headers,elf64_header,ifs);
        init_map_sgm_sec(map_sgm_sec,pro64_headers,sec64_headers);
        pshdr(elf64_header,sec64_headers,ifs);
        pphdr(pro64_headers);
        pmap_sgm_sec(map_sgm_sec,sec64_headers,elf64_header,ifs);
    }else if(elf_magic[EI_CLASS]==ELFCLASSNUM)
    {
        //没用
    }

    delete []elf_magic;  //delete 1
    if(elf32_header!=NULL)delete[] elf32_header;
    if(elf64_header!=NULL)delete[] elf64_header;

    return 0;
}

    template <typename T>
int __pehdr(T* ehdr)
{
    std::string s;
    //文件类型
    switch(ehdr->e_type)
    {
        case ET_NONE:s=INF_ET_NONE;break;
        case ET_REL:s=INF_ET_REL;break;
        case ET_EXEC:s=INF_ET_EXEC;break;
        case ET_DYN:s=INF_ET_DYN;break;
        case ET_CORE:s=INF_ET_CORE;break;
        case ET_NUM:s=INF_ET_NUM;break;
        case ET_LOOS:s=INF_ET_LOOS;break;
        case ET_HIOS:s=INF_ET_HIOS;break;
        case ET_LOPROC:s=INF_ET_LOPROC;break;
        case ET_HIPROC:s=INF_ET_HIPROC;break;
        default:s=INF_ET_NONE;
    }
    std::cout<<"Header of ELF :"<<std::endl;
    std::cout<<std::hex;
    std::cout<<"Type: "<<s<<std::endl;
    //版本
    std::cout<<"Version: 0x"<<ehdr->e_version<<std::endl;
    //程序入口地址
    std::cout<<"Entry point address: 0x"<<ehdr->e_entry<<std::endl;
    std::cout<<std::dec;
    //Start of program headers
    std::cout<<"Start of program headers: "<<ehdr->e_phoff<<std::endl;
    //Size of program headers
    std::cout<<"Size of program headers: "<<ehdr->e_phentsize<<std::endl;
    //Number of program headers 
    std::cout<<"Number of program headers: "<<ehdr->e_phnum<<std::endl;
    //Start of section headers
    std::cout<<"Start of section headers: "<<ehdr->e_shoff<<std::endl;
    //Size of section headers
    std::cout<<"Size of section headers: "<<ehdr->e_shentsize<<std::endl;
    //Number of section headers
    std::cout<<"Number of section headers: "<<ehdr->e_shnum<<std::endl;
    //Flags
    //Size of header
    return 0;
}

int pehdr(Elf32_Ehdr *ehdr)
{
    __pehdr<Elf32_Ehdr>(ehdr);
    return 0;
}

int pehdr(Elf64_Ehdr* ehdr)
{
    __pehdr<Elf64_Ehdr>(ehdr);
    return 0;
}

    template <typename T1,typename T2>
void init_sec_headers(std::vector<T1> &shdr,T2 *ehdr,std::fstream &ifs)
{
    //切换到sec Header的起始位置
    ifs.seekg(ehdr->e_shoff,std::ios::beg);
    for(int i = 0;i<ehdr->e_shnum;++i)
    {
        T1 t;
        ifs.read((char*)&t,sizeof(T1));
        shdr.push_back(t);
    }
}
    template <typename T1,typename T2>
void init_pro_headers(std::vector<T1> &phdr,T2 *ehdr,std::fstream &ifs)
{
    //切换到program Header的起始位置
    ifs.seekg(ehdr->e_phoff,std::ios::beg);
    for(int i = 0;i<ehdr->e_phnum;++i)
    {
        T1 t;
        ifs.read((char*)&t,sizeof(T1));
        phdr.push_back(t);
    }
}


    template <typename T1,typename T2>
std::string get_sec_name(T1 strtaboff,T2 offset,std::fstream &ifs)
{
    std::string strs;
    ifs.seekg(strtaboff+offset,std::ios::beg);
    std::getline(ifs,strs,'\0');
    return strs;
}

    template <typename T1,typename T2>
void pshdr(T1 *elf_header,T2 &sec_headers,std::fstream &ifs)
{
    std::cout<<"\nSection Headers:"<<std::endl;
    for(int i = 0;i!=elf_header->e_shnum;++i) {
        std::string s_name = get_sec_name(sec_headers[elf_header->e_shstrndx].sh_offset,
                sec_headers[i].sh_name,
                ifs);
        std::cout<<i<<" "<<s_name<<" "<<sec_headers[i].sh_type<<" "<<std::endl;
    }
}

    template <typename T>
void pphdr(std::vector<T> &phdrs)
{
    std::cout<<"\nSegments:"<<std::endl;
    for(int i = 0;i!=phdrs.size();++i)
    {
        std::cout<<"["<<i<<"] "<< phdrs[i].p_type<<" "<<phdrs[i].p_offset<<" 0x"<<std::hex<<phdrs[i].p_vaddr<<" 0x"
            <<phdrs[i].p_paddr<<" "<<std::dec<<phdrs[i].p_filesz<<" "<<phdrs[i].p_memsz<<" "<<phdrs[i].p_flags<<" "
            <<phdrs[i].p_align<<std::endl;
    }

}

    template <typename T1,typename T2>
void init_map_sgm_sec(MAP_SGM_SEC & map_sgm_sec,const std::vector<T1> & phdrs,const std::vector<T2> & shdrs)
{
    for(int pi = 0;pi!=phdrs.size();++pi)
    {
        std::vector<uint64_t> tv;
        map_sgm_sec.push_back(tv);	
    }
    for(int pi = 0;pi!=phdrs.size();++pi)
    {
        for(int si = 0;si!=shdrs.size();++si)
        {
            if(shdrs[si].sh_offset>=phdrs[pi].p_offset &&
                    shdrs[si].sh_offset+shdrs[si].sh_size<= phdrs[pi].p_offset+phdrs[pi].p_filesz)
            {
                map_sgm_sec[pi].push_back(shdrs[si].sh_name);
            }
        }
    }

}


    template <typename T1,typename T2>
void pmap_sgm_sec(const MAP_SGM_SEC &map_sgm_sec,const T1 & sec_headers,const T2 & elf_header,std::fstream &ifs)
{
    std::cout<<"\nMap of segments and sections\nSegments \tSections"<<std::endl;
    for(int i =  0 ;i!=map_sgm_sec.size();++i)
    {
        std::cout<<"["<<i<<"] ";
        for(int j = 0;j!=map_sgm_sec[i].size();++j)
        {
            std::cout<<get_sec_name(sec_headers[elf_header->e_shstrndx].sh_offset,
                    map_sgm_sec[i][j],
                    ifs)<<" ";
        }
        std::cout<<std::endl;
    }

}









