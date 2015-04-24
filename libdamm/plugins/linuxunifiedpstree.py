__author__ = 'jonathan'
import libdamm.memory_object as memobj


def getPluginObject(vol):
    '''
    Aid for introspection to load plugins

    @return: a ProcessSet instance
    '''
    return LinuxUnifiedpstreeSet(vol)


def getFields():
    '''
    Aid for introspection to load plugins

    @return: ordered list of Process fields keys
    '''
    return LinuxUnifiedpstree().get_field_keys()


class LinuxUnifiedpstreeSet(memobj.MemObjectSet):
    '''
    Manage sets of Windows processes parsed from memory dumps
    '''
    @staticmethod
    def get_field_typedefs():
        '''
        @return: the type definitions for filtering for Process memobjs
        '''
        defs = {}
        defs['PID'] = ['Task_PID']
        defs['string'] = ['Task_Name']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        self.vol = vol


    def get_all(self):
        '''
        not implemented
        '''



    def get_child(self):
        return LinuxUnifiedpstree()


    def get_unique_id(self, proc):
        '''
        @return: the default unique id for Process memobjs
        '''
        return (proc.fields['Task_PID'], proc.fields['Task_Name'],proc.fields['Task_PPID'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['Task_PID'] if x.fields['Task_PID'] != '' else 0))
        return elems


class LinuxUnifiedpstree(memobj.MemObject):

    def __init__(self, task=None, xview=None, offset=None):
        # Must init superclass
        off = str(hex(offset)).rstrip('L') if offset else None
        memobj.MemObject.__init__(self, off)

        # These are all of the process fields we know about
        self.fields['Task_Name'] = ''
        self.fields['Level'] = ''
        self.fields['Task_PID'] = ''
        self.fields['Task_PPID'] = ''
        self.fields['Task_UID'] = ''
        self.fields['Task_GID'] = ''
        self.fields['Task_EUID'] = ''