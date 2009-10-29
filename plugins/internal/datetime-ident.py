'''
Created on 20 Sep 2009

@author: Mike Auty
'''

import volatility.timefmt as timefmt
import volatility.obj as obj
import volatility.win32 as win32
import volatility.utils as utils
import volatility.commands as commands
import volatility.debug as debug

#pylint: disable-msg=C0111

class datetime(commands.command):
    """Get date/time information for image"""
    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        dt = data['ImageDatetime'].as_datetime()

        outfd.write("Image date and time       : {0}\n".format(data['ImageDatetime']))
        outfd.write("Image local date and time : {0}\n".format(timefmt.display_datetime(dt, data['ImageTz'])))

    def calculate(self):
        addr_space = utils.load_as()

        return self.get_image_time(addr_space)

    def get_image_time(self, addr_space):
        # Get the Image Datetime
        result = {}
        k = obj.Object("_KUSER_SHARED_DATA",
                              offset=win32.info.KUSER_SHARED_DATA,
                              vm=addr_space)
        
        result['ImageDatetime'] = k.SystemTime
        result['ImageTz'] = timefmt.OffsetTzInfo(-k.TimeZoneBias.as_windows_timestamp() / 10000000)

        return result

class ident(datetime):
    """ Identify information for the image """
    def __init__(self, args=None):
        datetime.__init__(self, args)
    
    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        
        dt = data['ImageDatetime'].as_datetime()

        outfd.write("              Image Name: {0}\n".format(data['ImageName']))
        outfd.write("              Image Type: {0}\n".format(data['ImageType']))
        outfd.write("                 VM Type: {0}\n".format(data['ImagePAE']))
        outfd.write("                     DTB: {0}\n".format(data['ImageDTB']))
        outfd.write("                Datetime: {0}\n".format(data['ImageDatetime']))
        outfd.write("          Local Datetime: {0}\n".format(timefmt.display_datetime(dt, data['ImageTz'])))
    
    def calculate(self):
        result = {}
        addr_space = utils.load_as()

        # Get the name
        tmpspace = addr_space
        result['ImageName'] = 'Unknown'
        while tmpspace is not None:
            if hasattr(tmpspace, 'name'):
                result['ImageName'] = tmpspace.name
            tmpspace = tmpspace.base

        # Get the Image Type
        result['ImageType'] = self.find_csdversion(addr_space)
        
        # Get the VM Type
        result['ImagePAE'] = 'nopae'
        if addr_space.pae:
            result['ImagePAE'] = 'pae'
        
        # Get the Image DTB
        result['ImageDTB'] = hex(addr_space.load_dtb())
        
        # Get the Image Datetime
        result.update(self.get_image_time(addr_space))

        return result

    def find_csdversion(self, addr_space):
        """Find the CDS version from an address space"""
        csdvers = {}
        for task in win32.tasks.pslist(addr_space):
            if task.Peb.CSDVersion:
                lookup = str(task.Peb.CSDVersion)
                csdvers[lookup] = csdvers.get(lookup, 0) + 1
                _, result = max([(v, k) for k, v in csdvers.items()])
                
                return str(result)
            
        return obj.NoneObject("Unable to find version")
