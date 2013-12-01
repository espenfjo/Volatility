# Volatility
# Copyright (C) 2007-2011 Volatile Systems
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

# ELF32 format: http://downloads.openwatcom.org/ftp/devel/docs/elf-32-gen.pdf

import volatility.obj as obj

class elf32_hdr(obj.CType):
    """An ELF32 header"""
    
    def program_headers(self):
        print self.e_phoff
        return obj.Object("Array", targetType = "elf32_phdr",
                          offset = self.obj_offset + self.e_phoff, 
                          count = self.e_phnum, vm = self.obj_vm)
    
class elf32_note(obj.CType):
    """An ELF32 note header"""
    
    def cast_descsz(self, obj_type):
        """Cast the descsz member as a specified type. 
        
        @param obj_type: name of the object 
        
        The descsz member is at a variable offset, which depends
        on the length of the namesz string which precedes it. The
        string is 8-byte aligned and can be zero. 
        """
        
        desc_offset = (self.obj_offset + 
                       self.obj_vm.profile.get_obj_size("elf32_note") +
                       ((((self.n_namesz - 1) >> 3) + 1) << 3))
                       
        return obj.Object(obj_type, offset = desc_offset, vm = self.obj_vm)    
    
class ELF32Modification(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update({
            'elf32_hdr' : [ 52, {
                'e_ident' : [ 0, ['String', dict(length = 16)]], 
                'e_type' : [ 16, ['Enumeration', dict(target = 'unsigned short', choices = {
                    0: 'ET_NONE', 
                    1: 'ET_REL', 
                    2: 'ET_EXEC', 
                    3: 'ET_DYN', 
                    4: 'ET_CORE', 
                    0xff00: 'ET_LOPROC', 
                    0xffff: 'ET_HIPROC'})]],
                'e_machine' : [ 18, ['unsigned short']], 
                'e_version' : [ 20, ['unsigned int']], 
                'e_entry' : [ 24, ['unsigned long']],
                'e_phoff' : [ 28, ['unsigned long']],
                'e_shoff' : [ 32, ['unsigned long']],
                'e_flags' : [ 36, ['unsigned int']],
                'e_ehsize' : [ 40, ['unsigned short']],
                'e_phentsize' : [ 42, ['unsigned short']],
                'e_phnum' : [ 44, ['unsigned short']],
                'e_shentsize' : [ 46, ['unsigned short']],
                'e_shnum' : [ 48, ['unsigned short']],
                'e_shstrndx' : [ 50, ['unsigned short']],
                }], 
            'elf32_phdr' : [ 32, {
                'p_type' : [ 0, ['Enumeration', dict(target = 'unsigned int', choices = {
                    0: 'PT_NULL', 
                    1: 'PT_LOAD',
                    2: 'PT_DYNAMIC', 
                    3: 'PT_INTERP', 
                    4: 'PT_NOTE', 
                    5: 'PT_SHLIB', 
                    6: 'PT_PHDR', 
                    7: 'PT_TLS', 
                    0x60000000: 'PT_LOOS', 
                    0x6fffffff: 'PT_HIOS', 
                    0x70000000: 'PT_LOPROC', 
                    0x7fffffff: 'PT_HIPROC'})]],
                'p_offset' : [ 4, ['unsigned long']],
                'p_vaddr' : [ 8, ['unsigned long']],
                'p_paddr' : [ 12, ['unsigned long']],
                'p_filesz' : [ 16, ['unsigned long']],
                'p_memsz' : [ 20, ['unsigned long']],
                'p_flags' : [ 24, ['unsigned int']],
                'p_align' : [ 28, ['unsigned long']],
                }], 
            'elf32_note' : [ 12, {
                'n_namesz' : [ 0, ['unsigned int']], 
                'n_descsz' : [ 4, ['unsigned int']], 
                'n_type' : [ 8, ['unsigned int']], 
                 ## FIXME: this must be cast to int() because the base AS (FileAddressSpace) read method doesn't understand NativeType.
                 ## Remove the cast after http://code.google.com/p/volatility/issues/detail?id=350 is fixed. 
                'namesz' : [ 12, ['String', dict(length = lambda x : int(x.n_namesz))]],
                }], 
        })
        profile.object_classes.update({'elf32_hdr': elf32_hdr, 'elf32_note': elf32_note})
