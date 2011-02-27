# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008-2011 Volatile Systems
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
@author:       Jamie Levy (Gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com

This file provides support for Windows Vista SP1. We provide a profile
for SP1.
"""

#pylint: disable-msg=C0111

import copy
import vista_sp0_x86
import vista_sp1_x86_vtypes
import vista_sp12_x86_syscalls
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import kdbg_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

vistasp1x86overlays = copy.deepcopy(vista_sp0_x86.vistasp0x86overlays)

vistasp1x86overlays['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x30\x03')]

vista_sp1_x86_vtypes.ntkrnlmp_types.update(crash_vtypes.crash_vtypes)
vista_sp1_x86_vtypes.ntkrnlmp_types.update(hibernate_vtypes.hibernate_vtypes)
vista_sp1_x86_vtypes.ntkrnlmp_types.update(kdbg_vtypes.kdbg_vtypes)
vista_sp1_x86_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes)
vista_sp1_x86_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes_vista)

class VistaSP1x86(windows.AbstractWindows):
    """ A Profile for Windows Vista SP1 x86 """
    abstract_types = vista_sp1_x86_vtypes.ntkrnlmp_types
    overlay = vistasp1x86overlays
    object_classes = copy.deepcopy(vista_sp0_x86.VistaSP0x86.object_classes)
    syscalls = vista_sp12_x86_syscalls.syscalls

