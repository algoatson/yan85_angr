from angr.simos import SimOS, register_simos
from angr.sim_procedure import SimProcedure
from angr.calling_conventions import SimStackArg, SimRegArg, register_syscall_cc, register_default_cc, SimCCUnknown
from yan85_arch import Yan85

class SimYan85(SimOS):
    SYSCALL_TABLE = {}

    def __init__(self, *args, **kwargs):
        super(SimYan85, self).__init__(*args, name="Yan85", **kwargs)

    def configure_project(self):
        super(SimYan85, self).configure_project()

    def state_blank(self, data_region_size=0x8000, **kwargs):
        state = super(SimYan85, self).state_blank(**kwargs)
        return state

    def state_entry(self, **kwargs):
        state = super(SimYan85, self).state_entry(**kwargs)
        return state

register_simos('Testing', SimYan85)
register_default_cc('Yan85', SimCCUnknown)
