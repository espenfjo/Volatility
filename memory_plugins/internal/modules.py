'''
Created on 25 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import forensics.commands
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.utils as utils

class modules(forensics.commands.command):
    """Print list of loaded modules"""

    def __init__(self, args=None):
        forensics.commands.command.__init__(self, args)
        self.profile = None

    def render_text(self, outfd, data):
        header = False
        
        for module in data:
            if not header:
                outfd.write("%-50s %-12s %-8s %s\n" % ('File', 'Base', 'Size', 'Name'))
                header = True
            outfd.write("%-50s 0x%0.10x 0x%0.6x %s\n" % (module.FullDllName, int(module.BaseAddress.value()), int(module.SizeOfImage), module.ModuleName))
        

    def calculate(self):
        result = {}
        self.profile = object2.Profile()

        addr_space = utils.load_as(self.opts)
        
        result = win32.modules.lsmod(addr_space, self.profile)

        return result