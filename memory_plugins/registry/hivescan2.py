# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import os
from forensics.win32.scan2 import PoolScanner
import forensics.commands
import forensics.conf
config=forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject

class PoolScanHiveFast2(PoolScanner):
    pool_size = 0x4a8
    pool_tag = "CM10"
    
    def __init__(self):
        PoolScanner.__init__(self)
        self.add_constraint(self.check_blocksize_equal)
        self.add_constraint(self.check_pagedpooltype)
        #self.add_constraint(self.check_poolindex)
        self.add_constraint(self.check_hive_sig)

    def check_hive_sig(self, found):
        sig = NewObject('_HHIVE', vm=self.buffer, offset=found+4).Signature.v()
        return sig == 0xbee0bee0

class hivescan(forensics.commands.command):
    """ Scan Physical memory for _CMHIVE objects (registry hives)

    You will need to obtain these offsets to feed into the hivelist command.
    """

    # Declare meta information associated with this plugin
    
    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )
    
    def execute(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(dict(type='physical'))
        
        print "%-15s %-15s" % ("Offset", "(hex)")
        for offset in PoolScanHiveFast2().scan(address_space):
            print "%-15s 0x%08X" % (offset, offset)