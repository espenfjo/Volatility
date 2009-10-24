'''
Created on 30 Sep 2009

@author: Mike Auty
'''

# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in 
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

import os.path
import volatility.conf
import taskmods
import volatility.debug as debug #pylint: disable-msg=W0611

config = volatility.conf.ConfObject()

# Inherit from dlllist just for the config options (__init__)
class vadinfo(taskmods.dlllist):
    """Dump the VAD info"""

    def render_text(self, outfd,data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            for vad in task.VadRoot.traverse():
                if vad == None:
                    outfd.write("Error: {0}".format(vad))
                else:
                    self.write_vad_short(outfd, vad)
                    try:
                        self.write_vad_control(outfd, vad)
                    except AttributeError:
                        pass
                    try:
                        self.write_vad_ext(outfd, vad)
                    except AttributeError:
                        pass
                    
                outfd.write("\n")

    def write_vad_short(self, outfd, vad):
        """Renders a text version of a Short Vad"""
        outfd.write("VAD node @{0:08x} Start {1:08x} End {2:08x} Tag {3:4}\n".format(
            vad.offset, vad.StartingVpn << 12, ((vad.EndingVpn + 1) << 12) - 1, vad.Tag))
        outfd.write("Flags: {0}\n".format(vad.Flags))
        outfd.write("Commit Charge: {0} Protection: {1:x}\n".format(
            vad.Flags.CommitCharge,
            vad.Flags.Protection >> 24))

    def write_vad_control(self, outfd, vad):
        """Renders a text version of a (non-short) Vad's control information"""
        CA = vad.ControlArea
        if not CA:
            #debug.b()
            return

        outfd.write("ControlArea @{0:08x} Segment {1:08x}\n".format(CA.dereference().offset, CA.Segment))
        outfd.write("Dereference list: Flink {0:08x}, Blink {1:08x}\n".format(CA.DereferenceList.Flink, CA.DereferenceList.Blink))
        outfd.write("NumberOfSectionReferences: {0:10} NumberOfPfnReferences:  {1:10}\n".format(CA.NumberOfSectionReferences, CA.NumberOfPfnReferences))
        outfd.write("NumberOfMappedViews:       {0:10} NumberOfSubsections:    {1:10}\n".format(CA.NumberOfMappedViews, CA.NumberOfSubsections))
        outfd.write("FlushInProgressCount:      {0:10} NumberOfUserReferences: {1:10}\n".format(CA.FlushInProgressCount, CA.NumberOfUserReferences))
        
        outfd.write("Flags: {0}\n".format(CA.Flags))

        if CA.FilePointer:
            outfd.write("FileObject @{0:08x}           , Name: {1}\n".format(CA.FilePointer.dereference().offset, CA.FilePointer.FileName))
        else:
            outfd.write("FileObject: none\n")

        outfd.write("WaitingForDeletion Event: {0:08x}\n".format(CA.WaitingForDeletion))
        outfd.write("ModifiedWriteCount: {0:8} NumberOfSystemCacheViews: {1:8}\n".format(CA.ModifiedWriteCount, CA.NumberOfSystemCacheViews))
    
    def write_vad_ext(self, outfd, vad):
        """Renders a text version of a Long Vad"""
        outfd.write("First prototype PTE: {0:08x} Last contiguous PTE: {1:08x}\n".format(vad.FirstPrototypePte, vad.LastContiguousPte))
        
        outfd.write("Flags2: {0}\n".format(vad.Flags2))
        outfd.write("File offset: {0:08x}\n".format(vad.Flags2.FileOffset))
        
        if (vad.Flags2.v() and vad.Flags2.LongVad):
            # FIXME: Add in the extra bits, after deciding on names for u3 and u4
            outfd.write("Extended information available\n")
    
class vadtree(vadinfo):
    """Walk the VAD tree and display in tree format"""
    
    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            levels = {}
            for vad in task.VadRoot.traverse():
                if vad:                    
                    level = levels.get(vad.Parent.dereference().offset, -1) + 1
                    levels[vad.offset] = level
                    outfd.write(" " * level + "{0:08x} - {1:08x}\n".format( 
                                vad.StartingVpn << 12,
                                ((vad.EndingVpn + 1) << 12) -1))

    def render_dot(self, outfd, data):
        for task in data:
            outfd.write("/" + "*" * 72 + "/\n")
            outfd.write("/* Pid: {0:6} */\n".format(task.UniqueProcessId))
            outfd.write("digraph processtree {\n")
            outfd.write("graph [rankdir = \"TB\"];\n")
            for vad in task.VadRoot.traverse():
                if vad:
                    if vad.Parent:
                        outfd.write("vad_{0:08x} -> vad_{1:08x}\n".format(vad.Parent.dereference().offset, vad.offset))                    
                    outfd.write("vad_{0:08x} [label = \"{{ {1}\\n{2:08x} - {3:08x} }}\""
                                "shape = \"record\" color = \"blue\"];\n".format(
                        vad.offset,
                        vad.Tag, 
                        vad.StartingVpn << 12,
                        ((vad.EndingVpn + 1) << 12) -1))
                    
            outfd.write("}\n")

class vadwalk(vadinfo):
    """Walk the VAD tree"""
    
    def render_text(self, outfd, data):
        for task in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: {0:6}\n".format(task.UniqueProcessId))
            outfd.write("Address  Parent   Left     Right    Start    End      Tag  Flags\n")
            for vad in task.VadRoot.traverse():
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad:
                    outfd.write("{0:08x} {1:08x} {2:08x} {3:08x} {4:08x} {5:08x} {6:4}\n".format(
                        vad.offset,
                        vad.Parent.dereference().offset or 0,
                        vad.LeftChild.dereference().offset or 0,
                        vad.RightChild.dereference().offset or 0,
                        vad.StartingVpn << 12,
                        ((vad.EndingVpn + 1) << 12) -1,
                        vad.Tag))

class vaddump(vadinfo):
    """Dumps out the vad sections to a file"""

    def __init__(self, *args):
        config.add_option('DUMP-DIR', short_option='D', default=None,
                          help='Directory in which to dump the VAD files')
        config.add_option('VERBOSE', short_option='v', default=False, type='bool',
                          help='Print verbose progress information')
        vadinfo.__init__(self, *args)

    def render_text(self, outfd, data):
        if config.DUMP_DIR == None:
            config.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(config.DUMP_DIR):
            config.error(config.DUMP_DIR + " is not a directory")

        for pid in data:
            outfd.write("Pid " + str(pid) + "\n")
            # Get the task and all process specific information
            task = data[pid].get('task', None)
            task_space = task.get_process_address_space()
            name = task.ImageFileName
            offset = task_space.vtop(task.offset)

            outfd.write("*" * 72 + "\n")
            for vad in data[pid]['vadlist']:
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad == None:
                    continue

                # Find the start and end range
                start = vad.StartingVpn << 12
                end = ((vad.EndingVpn + 1) << 12) - 1
                if start > 0xFFFFFFFF or end > (0xFFFFFFFF << 12):
                    continue

                # Open the file and initialize the data
                f = open(os.path.join(config.DUMP_DIR, "{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(name, offset, start, end)), 'wb')
                range_data = ""
                num_pages = (end - start + 1) >> 12

                for i in range(0, num_pages):
                    # Run through the pages gathering the data
                    page_addr = start + (i * 0x1000)
                    if not task_space.is_valid_address(page_addr):
                        range_data += ('\0' * 0x1000)
                        continue
                    page_read = task_space.read(page_addr, 0x1000)
                    if page_read == None:
                        range_data = range_data + ('\0' * 0x1000)
                    else:
                        range_data = range_data + page_read

                if config.VERBOSE:
                    outfd.write("Writing VAD for " + ("{0}.{1:x}.{2:08x}-{3:08x}.dmp".format(name, offset, start, end)) + "\n")
                f.write(range_data)
                f.close()

