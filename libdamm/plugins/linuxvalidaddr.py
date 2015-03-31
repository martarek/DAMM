__author__ = 'jonathan'
import libdamm.memory_object as memobj


def getPluginObject(vol):
    '''
    Aid for introspection to load plugins

    @return: a ProcessSet instance
    '''
    return LinuxValidaddrSet(vol)


def getFields():
    '''
    Aid for introspection to load plugins

    @return: ordered list of Process fields keys
    '''
    return LinuxValidaddr().get_field_keys()


class LinuxValidaddrSet(memobj.MemObjectSet):
    '''
    Manage sets of Windows processes parsed from memory dumps
    '''
    @staticmethod
    def get_field_typedefs():
        '''
        @return: the type definitions for filtering for Process memobjs
        '''
        defs = {}
        defs['PID'] = ['PID']
        defs['string'] = ['Name']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        self.vol = vol


    def get_all(self):
        '''
        not implemented
        '''



    def get_child(self):
        return LinuxValidaddr()


    def get_unique_id(self, proc):
        '''
        @return: the default unique id for Process memobjs
        '''
        return (proc.fields['PID'], proc.fields['Name'], proc.fields['addr'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['PID'] if x.fields['PID'] != '' else 0))
        return elems


class LinuxValidaddr(memobj.MemObject):

    def __init__(self, task=None, xview=None, offset=None):
        # Must init superclass
        off = str(hex(offset)).rstrip('L') if offset else None
        memobj.MemObject.__init__(self, off)

        # These are all of the process fields we know about
        self.fields['Name'] = str(task.comm) if task else ''
        self.fields['PID'] = str(task.pid) if task else ''
        self.fields['StartTime'] = str(task.pid) if task else ''
        self.fields['addr'] = ''
        self.fields['size'] = ''