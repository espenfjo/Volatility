""" General debugging framework """
import forensics.conf
config = forensics.conf.ConfObject()
import pdb

def debug(msg, level=1):
    if config.DEBUG >= level:
        print msg

def b():
    pdb.set_trace()
