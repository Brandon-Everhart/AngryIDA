'''
angr plug-in for IDA Pro.

Integrates point and click use of the angr binary analysis framework
inside of IDA Pro. The plug-in adds a sub menu, called AngryIDA, to
IDA View-A's pop-up context menu. Inside the IDA View-A window
right-click and expand the AngryIDA menu item to use.
'''

from __future__ import print_function
import angr
import claripy
import idaapi #pylint: disable=import-error
from idaapi import Form #pylint: disable=import-error


FIND_ADDRS = []
AVOID_ADDRS = []
EXP_OPTS = {
    "load":{
        "auto_load_libs":False
    },
    "state":{
        "discard_lazy_solves":True
    },
    "path_group":{
        "immutable":False
    },
    "time_limit":{
        "minutes":10
    },
    "stdin":{
        "length":-1,
        "ascii":False,
        "null":False,
        "white_space":False,
        "newline":True
    },
    "args":{
        "length":-1
    }
}

#----------------------------------------------------------------------------------
# Possible solution to limiting angr exploring the binary. Ideas:
#      - Limit time
#      - Limit RAM
#      - Limit CPU
#
# import sys
# import thread
# import threading
# from time import sleep
#
# def quit_thread(fn_name):
#     print('{0} took too long'.format(fn_name), file=sys.stderr)
#     thread.interrupt_main()
#
# def time_limit(minutes):
#     def decorate(fn):
#         def internal(*args, **kwargs):
#             timer = threading.Timer(minutes, quit_thread, args=[fn.__name__])
#             timer.start()
#             try:
#                 result = fn(*args, **kwargs)
#             finally:
#                 timer.cancel()
#             return result
#         return internal
#     return decorate
#----------------------------------------------------------------------------------

class TestEmbeddedChooserClass(Choose2):
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
    """
    def __init__(self, title, nb=5, flags=0):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        Choose2.__init__(
            self,
            title,
            [["Address", 10], ["Name", 30]],
            embedded=True,
            width=30,
            height=20,
            flags=flags
        )
        self.n = 0
        self.items = [self.make_item()]*(nb+1)
        self.icon = 5
        self.selcount = 0

    def make_item(self):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def OnClose(self):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        pass

    def OnGetLine(self, n):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

class ExpFormOpts(Form):
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
    """
    def __init__(self):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        self.invert = False
        self.EChooser = TestEmbeddedChooserClass("E1", flags=Choose2.CH_MULTI)
        Form.__init__(self, r"""STARTITEM {id:rDiscardLazySolves}
Options
<Discard LAZY_SOLVES:{rDiscardLazySolves}>
<Immutable:{rImmutable}>
<Auto Load Libs:{rAutoLoadLibs}>{cGroup1}>
<Time Limit:{iTimeLimit}>
""", {
    'cGroup1': Form.ChkGroupControl(("rDiscardLazySolves", "rImmutable", "rAutoLoadLibs")),
    'iTimeLimit':Form.NumericInput(),
    })

class ExpFormStdin(Form):
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
    """
    def __init__(self):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        self.invert = False
        self.EChooser = TestEmbeddedChooserClass("E1", flags=Choose2.CH_MULTI)
        Form.__init__(self, r"""STARTITEM
Symbolic stdin
<##Enter length of stdin:{iStdinLen}>
<Ending newline:{rNewline}>
<Allow Null:{rNull}>
<White Space:{rWhite}>
<Force ASCII:{rASCII}>{cGroup2}>
""", {
    'iStdinLen':Form.NumericInput(),
    'cGroup2': Form.ChkGroupControl(("rNewline", "rNull", "rWhite", "rASCII"))
    })

class ExpFormArgs(Form):
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
    """
    def __init__(self):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        self.invert = False
        self.EChooser = TestEmbeddedChooserClass("E1", flags=Choose2.CH_MULTI)
        Form.__init__(self, r"""STARTITEM
Arguments 
<##Enter length of argument:{iArgLen}>
""", {
    'iArgLen':Form.NumericInput()
    })

class ActionHandler(idaapi.action_handler_t):
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
    """
    def __init__(self, action):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        if self.action == "Finds:Set":
            find_set()
        elif self.action == "Finds:Remove":
            find_remove()
        elif self.action == "Finds:Print":
            find_view()
        elif self.action == "Avoids:Set":
            avoid_set()
        elif self.action == "Avoids:Remove":
            avoid_remove()
        elif self.action == "Avoids:Print":
            avoid_view()
        elif self.action == "Explore:Run":
            explore_run()
        elif self.action == "Explore:Options":
            explore_options()
        elif self.action == "Explore:Stdin":
            explore_stdin()
        elif self.action == "Explore:Arguments":
            explore_arguments()
        elif self.action == "Refresh:Refresh":
            refresh()
        elif self.action == "Quit:Quit":
            my_quit()

    def update(self, ctx):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        return idaapi.AST_ENABLE_ALWAYS

class Hooks(idaapi.UI_Hooks):
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
    """
    @staticmethod
    def finish_populating_tform_popup(form, popup):
        """
        Arguments:
        Return Value:
        Description:
            -
        TODO:
            - Doc String
        """
        if idaapi.get_tform_title(form) == "IDA View-A":
            idaapi.attach_action_to_popup(form, popup, "Finds:Set", "AngryIDA/Finds/")
            idaapi.attach_action_to_popup(form, popup, "Finds:Remove", "AngryIDA/Finds/")
            idaapi.attach_action_to_popup(form, popup, "Finds:Print", "AngryIDA/Finds/")
            idaapi.attach_action_to_popup(form, popup, "Avoids:Set", "AngryIDA/Avoids/")
            idaapi.attach_action_to_popup(form, popup, "Avoids:Remove", "AngryIDA/Avoids/")
            idaapi.attach_action_to_popup(form, popup, "Avoids:Print", "AngryIDA/Avoids/")
            idaapi.attach_action_to_popup(form, popup, "Explore:Run", "AngryIDA/Explore/")
            idaapi.attach_action_to_popup(form, popup, "Explore:Options", "AngryIDA/Explore/")
            idaapi.attach_action_to_popup(form, popup, "Explore:Stdin", "AngryIDA/Explore/")
            idaapi.attach_action_to_popup(form, popup, "Explore:Arguments", "AngryIDA/Explore/")
            idaapi.attach_action_to_popup(form, popup, "Refresh:Refresh", "AngryIDA/")
            idaapi.attach_action_to_popup(form, popup, "Quit:Quit", "AngryIDA/")

def set_line_color(color, addr=here(), item=CIC_ITEM): #pylint: disable=undefined-variable
    """
    Arguments:
        Mandatory:
            - ( Name: color,
                Position: 0,
                Type: int,
                Value: hex/int color value )
        Optional:
            - ( Name: addr,
                Position: 1,
                Type: int,
                Default: here(),
                Value: hex/int memory address )
            - ( Name: item,
                Position: 2,
                Type: IDA Item,
                Default: CIC_ITEM,
                Value: IDA Item )
    Return: None
    Description:
        - Change instruction line color in IDA with specified color and address.
        Disabled pylint errors due to IDA function calls.
    TODO:
        - Nothing currently.
    """
    SetColor(addr, item, color) #pylint: disable=undefined-variable

def find_set():
    """
    Arguments: None
    Return Value: None
    Description:
        - Function is called by the Finds:Set action and adds the address which is
        currently selected in IDA View-A to the list of addresses angr will find
        while exploring.
    TODO:
        - Nothing.
    """
    addr = idaapi.get_screen_ea()
    if addr in AVOID_ADDRS:
        AVOID_ADDRS.remove(addr)
        print("AngryIDA: Removed avoid address [%s]" % hex(addr))
    FIND_ADDRS.append(addr)
    set_line_color(0x208020, addr)
    print("AngryIDA: Added find address [%s]" % hex(addr))

def find_remove():
    """
    Arguments: None
    Return Value: None
    Description:
        - Function is called by the Finds:Remove action and removes the address which
        is currently selected in IDA View-A from the list of addresses angr will find
        while exploring.
    TODO:
        - Nothing.
    """
    addr = idaapi.get_screen_ea()
    if addr in FIND_ADDRS:
        FIND_ADDRS.remove(addr)
        set_line_color(0xffffff, addr)
        print("AngryIDA: Removed find address [%s]" % hex(addr))

def find_view():
    """
    Arguments: None
    Return Value: None
    Description:
        - Function is called by the Finds:Print action and displays
        all the address in the global FIND_ADDRS list. This is
        displayed in the IDA Pro Output Window.
    TODO:
        - Nothing
    """
    print("AngryIDA:\n\tFind Addresses")
    for addr in FIND_ADDRS:
        print("\t\t%s" % hex(addr))

def avoid_set():
    """
    Arguments:
    Return Value:
    Description:
        - Function is called by the Avoids:Set action and adds the address which is
        currently selected in IDA View-A to the list of addresses angr will avoid
        while exploring.
    TODO:
        - Nothing.
    """
    addr = idaapi.get_screen_ea()
    if addr in FIND_ADDRS:
        FIND_ADDRS.remove(addr)
        print("AngryIDA: Removed find address [%s]" % hex(addr))
    AVOID_ADDRS.append(addr)
    set_line_color(0x2020c0, addr)
    print("AngryIDA: Added avoid address [%s]" % hex(addr))

def avoid_remove():
    """
    Arguments: None
    Return Value: None
    Description:
        - Function is called by the Avoids:Remove action and removes the address
        which is currently selected in IDA View-A from the list of addresses angr will
        avoid while exploring.
    TODO:
        - Nothing.
    """
    addr = idaapi.get_screen_ea()
    if addr in AVOID_ADDRS:
        AVOID_ADDRS.remove(addr)
        set_line_color(0xffffff, addr)
        print("AngryIDA: Removed avoid address [%s]" % hex(addr))

def avoid_view():
    """
    Arguments: None
    Return Value: None
    Description:
        - Function is called by the Avoids:Print action and displays
        all the address in the global AVOID_ADDRS list. This is
        displayed in the IDA Pro Output Window.
    TODO:
        - Nothing
    """
    print("\tAvoid Addresses")
    for addr in AVOID_ADDRS:
        print("\t\t%s" % hex(addr))

#@time_limit(EXP_OPTS["time_limit"]["minutes"])
def explore_run():
    """
    Arguments:
    Return Value:
    Description:
        -
    TODO:
        - Doc String
        - Handle Multiple Symbolic Arguments
        - Handle Multiple Symbolic stdin
        - Force ASCII printable for stdin
        - Handle Symbolic Files
        - Handle Symbolic Memory
        -
    """
    print(EXP_OPTS["time_limit"]["minutes"])
    binary_file = idaapi.get_input_file_path()
    proj = angr.Project(binary_file, load_options=EXP_OPTS["load"])

    arg_len = EXP_OPTS["args"]["length"]
    if arg_len > 0:
        argv1 = claripy.BVS("argv1", arg_len * 8)
        initial_state = proj.factory.entry_state(args=[binary_file, argv1])
    else:
        initial_state = proj.factory.entry_state()

    if EXP_OPTS["state"]["discard_lazy_solves"]:
        initial_state.options.discard("LAZY_SOLVES")

    stdin_len = EXP_OPTS["stdin"]["length"]
    if stdin_len > 0:
        for _ in range(0, stdin_len-1):
            k = initial_state.posix.files[0].read_from(1)
            if not EXP_OPTS["stdin"]["null"]:
                initial_state.se.add(k != 0)
            if not EXP_OPTS["stdin"]["white_space"]:
                initial_state.se.add(k != 10)
            #if EXP_OPTS["stdin"]["ascii"]:
                # NEED TO FIX THIS
                #initial_state.se.add(33 <= k)
                #initial_state.se.add(k <= 126)

        k = initial_state.posix.files[0].read_from(1)
        if EXP_OPTS["stdin"]["newline"]:
            initial_state.se.add(k == 10)

        initial_state.posix.files[0].seek(0)
        initial_state.posix.files[0].length = stdin_len

    immutable = EXP_OPTS["path_group"]["immutable"]
    sim_manager = proj.factory.simulation_manager(initial_state, immutable=immutable)
    sim_manager.explore(find=FIND_ADDRS, avoid=AVOID_ADDRS)

    try:
        found = sim_manager.found[0].state
        found.posix.files[0].seek(0)
        print("Found: "+ found.se.eval(found.posix.files[0].read_from(stdin_len), cast_to=str))
    except IndexError:
        print("No stdin found.")

    try:
        found = sim_manager.found[0]
        print(found.state.se.eval(argv1, cast_to=str))
    except IndexError:
        print("No arguments found.")

def explore_options():
    """
    Arguments: None
    Return Value: None
    Description:
        -
    TODO:
        - Doc String.
    """
    EXP_FORM_OPTS.Execute()
    EXP_OPTS["state"]["discard_lazy_solves"] = EXP_FORM_OPTS.rDiscardLazySolves.checked
    EXP_OPTS["load"]["auto_load_libs"] = EXP_FORM_OPTS.rAutoLoadLibs.checked
    EXP_OPTS["path_group"]["immutable"] = EXP_FORM_OPTS.rImmutable.checked
    EXP_OPTS["time_limit"]["minutes"] = EXP_FORM_OPTS.iTimeLimit.value

def explore_stdin():
    """
    Arguments: None
    Return Value: None
    Description:
        -
    TODO:
        - Doc String.
    """
    EXP_FORM_STDIN.Execute()
    EXP_OPTS["stdin"]["newline"] = EXP_FORM_STDIN.rNewline.checked
    EXP_OPTS["stdin"]["null"] = EXP_FORM_STDIN.rNull.checked
    EXP_OPTS["stdin"]["ascii"] = EXP_FORM_STDIN.rASCII.checked
    EXP_OPTS["stdin"]["white_space"] = EXP_FORM_STDIN.rWhite.checked
    EXP_OPTS["stdin"]["length"] = EXP_FORM_STDIN.iStdinLen.value

def explore_arguments():
    """
    Arguments: None
    Return Value: None
    Description:
        -
    TODO:
        - Doc String.
    """
    EXP_FORM_ARGS.Execute()
    EXP_OPTS["args"]["length"] = EXP_FORM_ARGS.iArgLen.value

def refresh():
    """
    Arguments: None
    Return Value: None
    Description:
        - Function is called by the Refresh:Refresh action and removes
        all the address in the global AVOID_ADDRS list and FIND_ADDRS list. Also
        removes all colored addresses in IDA View-A. Success/Fail is displayed
        in the IDA Pro Output Window.
    TODO:
        - Nothing.
    """
    for addr in FIND_ADDRS:
        set_line_color(0xffffff, addr)
    del FIND_ADDRS[:]
    for addr in AVOID_ADDRS:
        set_line_color(0xffffff, addr)
    del AVOID_ADDRS[:]

    if len(FIND_ADDRS) != 0 and len(AVOID_ADDRS) != 0:
        print("AngryIDA: Refresh Failed")
    else:
        print("AngryIDA: Refresh completed.")

def my_quit():
    """
    Arguments: None
    Return Value: None
    Description:
        -
    TODO:
        - Stop script
        - Clean state
        - Remove context menu
        - Undo any hot-keys (No hot-keys used currently)
        - Reset changes to IDA views (Color/highlighting)
        - Description
    """
    return None

#------------------------------MAIN------------------------------------
EXP_FORM_OPTS = ExpFormOpts()
EXP_FORM_STDIN = ExpFormStdin()
EXP_FORM_ARGS = ExpFormArgs()

# Compile (in order to populate the controls)
EXP_FORM_OPTS.Compile()
EXP_FORM_STDIN.Compile()
EXP_FORM_ARGS.Compile()

# Set some defaults
EXP_FORM_OPTS.rDiscardLazySolves.checked = True
EXP_FORM_OPTS.iTimeLimit.value = 10
EXP_FORM_STDIN.rNewline.checked = True

# Create actions from context menu
ACTION_FS = idaapi.action_desc_t('Finds:Set', 'Set', ActionHandler("Finds:Set"))
ACTION_FR = idaapi.action_desc_t('Finds:Remove', 'Remove', ActionHandler("Finds:Remove"))
ACTION_FP = idaapi.action_desc_t('Finds:Print', 'Print', ActionHandler("Finds:Print"))
ACTION_AS = idaapi.action_desc_t('Avoids:Set', 'Set', ActionHandler("Avoids:Set"))
ACTION_AR = idaapi.action_desc_t('Avoids:Remove', 'Remove', ActionHandler("Avoids:Remove"))
ACTION_AP = idaapi.action_desc_t('Avoids:Print', 'Print', ActionHandler("Avoids:Print"))
ACTION_ER = idaapi.action_desc_t('Explore:Run', 'Run', ActionHandler("Explore:Run"))
ACTION_EO = idaapi.action_desc_t('Explore:Options', 'Options', ActionHandler("Explore:Options"))
ACTION_ES = idaapi.action_desc_t('Explore:Stdin', 'Stdin', ActionHandler("Explore:Stdin"))
ACTION_EA = idaapi.action_desc_t('Explore:Argument', 'Argument', ActionHandler("Explore:Argument"))
ACTION_RR = idaapi.action_desc_t('Refresh:Refresh', 'Refresh', ActionHandler("Refresh:Refresh"))
ACTION_QQ = idaapi.action_desc_t('Quit:Quit', 'Quit', ActionHandler("Quit:Quit"))

# Register Actions
idaapi.register_action(ACTION_FS)
idaapi.register_action(ACTION_FR)
idaapi.register_action(ACTION_FP)
idaapi.register_action(ACTION_AS)
idaapi.register_action(ACTION_AR)
idaapi.register_action(ACTION_AP)
idaapi.register_action(ACTION_ER)
idaapi.register_action(ACTION_EO)
idaapi.register_action(ACTION_ES)
idaapi.register_action(ACTION_EA)
idaapi.register_action(ACTION_RR)
idaapi.register_action(ACTION_QQ)

HOOKS = Hooks()
HOOKS.hook()
