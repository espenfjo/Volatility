# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

""" These are standard address spaces supported by Volatility """
import struct
import volatility.addrspace as addrspace
import volatility.conf
config = volatility.conf.ConfObject()
import volatility.debug as debug #pylint: disable-msg=W0611
import urllib
import os

#pylint: disable-msg=C0111

## This module requires a filename to be passed by the user
config.add_option("USE-OLD-AS", action="store_true", default=False, 
                  help = "Use the legacy address spaces")

        

def write_callback(option, _opt_str, _value, parser, *_args, **_kwargs):
    """Callback function to ensure that write support is only enabled if user repeats a long string
    
       This call back checks whether the user really wants write support and then either enables it
       (for all future parses) by changing the option to store_true, or disables it permanently
       by ensuring all future attempts to store the value store_false.
    """
    if not hasattr(parser.values, 'write'):
        # We don't want to use config.outfile, since this should always be seen by the user
        option.dest = "write"
        option.action = "store_false"
        parser.values.write = False
        for _ in range(3):
            testphrase = "Yes, I want to enable write support"
            response = raw_input("Write support requested.  Please type \"" + testphrase +
                                 "\" below precisely (case-sensitive):\n")
            if response == testphrase:
                option.action = "store_true"
                parser.values.write = True
                return
        print "Write support disabled."

config.add_option("WRITE", short_option='w', action="callback", default=False,
                  help = "Enable write support", callback=write_callback)

class FileAddressSpace(addrspace.BaseAddressSpace):
    """ This is a direct file AS.

    For this AS to be instanitiated, we need

    1) A valid config.FILENAME

    2) no one else has picked the AS before us
    
    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort
    order = 100
    def __init__(self, base, layered=False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, **kwargs)
        assert base == None or layered, 'Must be first Address Space'
        assert config.LOCATION.startswith("file:"), 'Location is not of file scheme'

        path = urllib.url2pathname(config.LOCATION[5:])
        assert os.path.exists(path), 'Filename must be specified and exist'
        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        if config.WRITE:
            self.mode += '+'
        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.offset = 0

    def fread(self, length):
        return self.fhandle.read(length)

    def read(self, addr, length):
        self.fhandle.seek(addr)        
        return self.fhandle.read(length)    

    def zread(self, addr, length):
        return self.read(addr, length)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def get_available_addresses(self):
        # TODO: Explain why this is always fsize - 1?
        yield (0, self.fsize - 1)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize - 1

    def close(self):
        self.fhandle.close()

    def write(self, addr, data):
        if not config.WRITE:
            return False
        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
        except IOError:
            return False
        return True

class PagedMemory(addrspace.BaseAddressSpace):
    """ Class to handle all the associated details of a paged address space
        
    Note: Pages can be of any size
    """
    def __init__(self, base, **kwargs):
        assert self.__class__.__name__ != 'PagedMemory', "Abstract Class - Never for instantiation directly"
        addrspace.BaseAddressSpace.__init__(self, base)

    def vtop(self, addr):
        """Abstract function that converts virtual (paged) addresses to physical addresses"""
        pass

    def get_available_pages(self):
        """A generator that returns (addr, size) for each of the virtual addresses present"""
        pass
    
    def get_available_addresses(self):
        """A generator that returns (addr, size) for each valid address block"""
        runLength = None
        currentOffset = None
        for (offset, size) in self.get_available_pages():
            if (runLength == None):
                runLength = size
                currentOffset = offset
            else:
                if (offset == (currentOffset + runLength)):
                    runLength += size
                else:
                    yield (currentOffset, runLength)
                    runLength = size
                    currentOffset = offset
        if (runLength != None and currentOffset != None):
            yield (currentOffset, runLength)
        raise StopIteration
        
    def is_valid_address(self, vaddr):
        """Returns whether a virtual address is valid"""
        if vaddr == None:
            return False
        try:    
            paddr = self.vtop(vaddr)
        except:
            return False
        if paddr == None:
            return False
        return self.base.is_valid_address(paddr)


class WritablePagedMemory(PagedMemory):
    """
    Mixin class that can be used to add write functionality
    to any standard address space that supports write() and
    vtop().
    """
    def __init__(self, base, **kwargs):
        assert self.__class__.__name__ != 'WritablePagedMemory', "Abstract Class - Never for instantiation directly"
        PagedMemory.__init__(self, base)
    
    def write(self, vaddr, buf):
        if not config.WRITE:
            return False
       
        length = len(buf)
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:        
            return False
        
        if length < first_block:
            return self.base.write(paddr, buf)

        self.base.write(paddr, buf[:first_block])
        buf = buf[first_block:]

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                raise Exception("Failed to write to page at {0:#x}".format(new_vaddr))
            if not self.base.write(paddr, buf[:0x1000]):
                return False
            new_vaddr = new_vaddr + 0x1000
            buf = buf[0x1000:]

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                raise Exception("Failed to write to page at {0:#x}".format(new_vaddr))
            assert len(buf) == left_over
            return self.base.write(paddr, buf)

    def write_long_phys(self, addr, val):
        if not config.WRITE:
            return False
        buf = struct.pack('=L', val)
        return self.base.write(addr, buf)