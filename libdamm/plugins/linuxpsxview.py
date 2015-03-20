__author__ = 'jonathan'
import libdamm.memory_object as memobj


def getPluginObject(vol):
    '''
    Aid for introspection to load plugins

    @return: a ProcessSet instance
    '''
    return LinuxPsxviewSet(vol)


def getFields():
    '''
    Aid for introspection to load plugins

    @return: ordered list of Process fields keys
    '''
    return LinuxPsxview().get_field_keys()


class LinuxPsxviewSet(memobj.MemObjectSet):
    '''
    Manage sets of Windows processes parsed from memory dumps
    '''
    @staticmethod
    def get_field_typedefs():
        '''
        @return: the type definitions for filtering for Process memobjs
        '''
        defs = {}
        defs['pid'] = ['pid', 'ppid']
        defs['time'] = ['create_time', 'exit_time']
        defs['string'] = ['name']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        self.vol = vol


    def get_all(self):
        '''
        Mimics Volatility's psxview, pslist, psscan, cmdline plugins
        '''
        import volatility.plugins.linux.psxview as psxview

        for offset, process, ps_sources in psxview.linux_psxview(self.vol.config).calculate():
            yield LinuxPsxview(process, ps_sources, offset)


    def get_child(self):
        return LinuxPsxview()


    def get_unique_id(self, proc):
        '''
        @return: the default unique id for Process memobjs
        '''
        return (proc.fields['pid'], proc.fields['name'], proc.fields['ppid'], proc.fields['Start Time'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['pid'] if x.fields['pid'] != '' else 0))
        return elems


class LinuxPsxview(memobj.MemObject):

    def __init__(self, task=None, xview=None, offset=None):

        # Must init superclass
        off = str(hex(offset)).rstrip('L') if offset else None
        memobj.MemObject.__init__(self, off)

        # These are all of the process fields we know about
        self.fields['name'] = str(task.comm) if task else ''
        self.fields['pid'] = str(task.pid) if task else ''
        self.fields['Start Time'] = str(task.get_task_start_time()) if task else ''

        self.fields['pslist'] = str(xview['pslist'].__contains__(offset)) if xview else ''
        self.fields['pid_hash'] = str(xview['pid_hash'].__contains__(offset)) if xview else ''
        self.fields['kmem_cache'] = str(xview['kmem_cache'].__contains__(offset)) if xview else ''
        self.fields['parents'] = str(xview['parents'].__contains__(offset)) if xview else ''
        self.fields['thread_leader'] = str(xview['thread_leaders'].__contains__(offset)) if xview else ''

