import libdamm.memory_object as memobj


def getPluginObject(vol):
    '''
    Aid for introspection to load plugins

    @return: a ProcessSet instance
    '''
    return LinuxPslistSet(vol)


def getFields():
    '''
    Aid for introspection to load plugins

    @return: ordered list of Process fields keys
    '''
    return LinuxPslist().get_field_keys()

class LinuxPslistSet(memobj.MemObjectSet):
    '''
    Manage sets of Windows processes parsed from memory dumps
    '''
    @staticmethod
    def get_field_typedefs():
        '''
        @return: the type definitions for filtering for Process memobjs
        '''
        defs = {}
        defs['pid'] = ['pid']
        defs['time'] = ['Start Time']
        defs['string'] = ['name']
        return defs


    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)

        self.vol = vol
        #self.vol.config.optparse_opts.output = "sqlite"
        #self.vol.config.optparse_opts.output_file


    def get_all(self):
        '''
        Mimics Volatility's  pslist
        '''
        import volatility.plugins.linux.pslist as pslist
        psl =pslist.linux_pslist(self.vol.config)
        for task in psl.calculate():
            if task.mm.pgd == None:
                dtb = task.mm.pgd
            else:
                dtb = psl.addr_space.vtop(task.mm.pgd) or task.mm.pgd
            yield LinuxPslist(task,dtb)


    def get_child(self):
        return LinuxPslist()


    def get_unique_id(self, proc):
        '''
        @return: the default unique id for Process memobjs
        '''
        return (proc.fields['Pid'], proc.fields['Name'], proc.fields['Start Time'])


    def sort_elems(self, elems):
        elems.sort(key=lambda x: int(x.fields['Pid'] if x.fields['Pid'] != '' else 0))
        return elems


class LinuxPslist(memobj.MemObject):
    def __init__(self, task=None,dtb=None):

        # Must init superclass
        off = str(hex(task.obj_offset)).rstrip('L') if task else None
        memobj.MemObject.__init__(self, off)

        # These are all of the process fields we know about
        self.fields['Name'] = str(task.comm) if task else ''
        self.fields['Pid'] = str(task.pid) if task else ''
        self.fields['Uid'] = str(task.uid) if task else ''
        self.fields['Gid'] = str(task.gid) if task else ''
        self.fields['DTB'] = str(dtb) if dtb else ''
        self.fields['Start Time'] = str(task.get_task_start_time()) if task else ''


