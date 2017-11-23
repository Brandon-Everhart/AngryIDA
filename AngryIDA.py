'''
angr plug-in for IDA Pro.

Integrates point and click use of the angr binary analysis framework
inside of IDA Pro. The plug-in adds a sub menu, called AngryIDA, to
IDA View-A's pop-up context menu. Inside the IDA View-A window
right-click and expand the AngryIDA menu item to use.
'''
from __future__ import print_function
import angr
import idaapi #pylint: disable=import-error

FIND_ADDRS = []
AVOID_ADDRS = []

class ActionHandler(idaapi.action_handler_t):
    """
    TODO
    """
    def __init__(self, action):
        """
        TODO
        """
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        """
        TODO
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
            explore()
        elif self.action == "Refresh:Refresh":
            refresh()
        elif self.action == "Quit:Quit":
            my_quit()

    def update(self, ctx):
        """
        TODO
        """
        return idaapi.AST_ENABLE_ALWAYS

class Hooks(idaapi.UI_Hooks):
    """
    TODO
    """
    def finish_populating_tform_popup(self, form, popup):
        """
        TODO
        """
        if idaapi.get_tform_title(form) == "IDA View-A":
            idaapi.attach_action_to_popup(form, popup, "Finds:Set", "AngryIDA/Finds/")
            idaapi.attach_action_to_popup(form, popup, "Finds:Remove", "AngryIDA/Finds/")
            idaapi.attach_action_to_popup(form, popup, "Finds:Print", "AngryIDA/Finds/")
            idaapi.attach_action_to_popup(form, popup, "Avoids:Set", "AngryIDA/Avoids/")
            idaapi.attach_action_to_popup(form, popup, "Avoids:Remove", "AngryIDA/Avoids/")
            idaapi.attach_action_to_popup(form, popup, "Avoids:Print", "AngryIDA/Avoids/")
            idaapi.attach_action_to_popup(form, popup, "Explore:Run", "AngryIDA/Explore/")
            idaapi.attach_action_to_popup(form, popup, "Refresh:Refresh", "AngryIDA/")
            idaapi.attach_action_to_popup(form, popup, "Quit:Quit", "AngryIDA/")

def set_line_color(color, addr=here(), item=CIC_ITEM): #pylint: disable=undefined-variable
    """
    Function: set_line_color
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
        Change instruction line color in IDA with specified color and address.
        Disabled pylint errors due to IDA function calls.
    TODO:
        Nothing currently.
    """
    SetColor(addr, item, color) #pylint: disable=undefined-variable

def find_set():
    """
    Arguments: None
    Return Value: None
    Description:
        - Toggles find address in list and color on screen.
    TODO:
        - Better description
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
        - Toggles find address in list and color on screen.
    TODO:
        - Better description
    """
    addr = idaapi.get_screen_ea()
    if addr in FIND_ADDRS:
        FIND_ADDRS.remove(addr)
        set_line_color(0xffffff, addr)
        print("AngryIDA: Removed find address [%s]" % hex(addr))

def find_view():
    '''
    TODO
    '''
    print("AngryIDA:\n\tFind Addresses")
    for addr in FIND_ADDRS:
        print("\t\t%s" % hex(addr))

def avoid_set():
    """
    TODO
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
    TODO
    """
    addr = idaapi.get_screen_ea()
    if addr in AVOID_ADDRS:
        AVOID_ADDRS.remove(addr)
        set_line_color(0xffffff, addr)
        print("AngryIDA: Removed avoid address [%s]" % hex(addr))

def avoid_view():
    '''
    TODO
    '''
    print("\tAvoid Addresses")
    for addr in AVOID_ADDRS:
        print("\t\t%s" % hex(addr))

def explore():
    """
    TODO
    """
    binary_file = idaapi.get_input_file_path()
    proj = angr.Project(binary_file, load_options={"auto_load_libs":False})
    initial_state = proj.factory.entry_state()
    initial_state.options.discard("LAZY_SOLVES")
    for _ in range(0, 32):
        k = initial_state.posix.files[0].read_from(1)
        initial_state.se.add(k != 0)
        initial_state.se.add(k != 10)

    # The last char of user input must be a newline
    k = initial_state.posix.files[0].read_from(1)
    initial_state.se.add(k == 10)

    # Reset the stdin to the beginning, 0
    initial_state.posix.files[0].seek(0)
    initial_state.posix.files[0].length = 33

    path_group = proj.factory.path_group(initial_state, immutable=False)
    path_group.explore(find=FIND_ADDRS, avoid=AVOID_ADDRS)

    found = path_group.found[0].state
    found.posix.files[0].seek(0)
    print("Found: "+ found.se.any_str(found.posix.files[0].read_from(33)))

def refresh():
    """
    TODO
    """
    print(FIND_ADDRS, AVOID_ADDRS)
    for addr in FIND_ADDRS:
        set_line_color(0xffffff, addr)
    del FIND_ADDRS[:]
    for addr in AVOID_ADDRS:
        set_line_color(0xffffff, addr)
    del AVOID_ADDRS[:]
    print("AngryIDA: Refresh completed.")

def my_quit():
    """
    TODO
    """
    return 1

ACTION_FS = idaapi.action_desc_t('Finds:Set', 'Set', ActionHandler("Finds:Set"))
ACTION_FR = idaapi.action_desc_t('Finds:Remove', 'Remove', ActionHandler("Finds:Remove"))
ACTION_FP = idaapi.action_desc_t('Finds:Print', 'Print', ActionHandler("Finds:Print"))
ACTION_AS = idaapi.action_desc_t('Avoids:Set', 'Set', ActionHandler("Avoids:Set"))
ACTION_AR = idaapi.action_desc_t('Avoids:Remove', 'Remove', ActionHandler("Avoids:Remove"))
ACTION_AP = idaapi.action_desc_t('Avoids:Print', 'Print', ActionHandler("Avoids:Print"))
ACTION_ER = idaapi.action_desc_t('Explore:Run', 'Run', ActionHandler("Explore:Run"))
ACTION_RR = idaapi.action_desc_t('Refresh:Refresh', 'Refresh', ActionHandler("Refresh:Refresh"))
ACTION_QQ = idaapi.action_desc_t('Quit:Quit', 'Quit', ActionHandler("Quit:Quit"))

idaapi.register_action(ACTION_FS)
idaapi.register_action(ACTION_FR)
idaapi.register_action(ACTION_FP)
idaapi.register_action(ACTION_AS)
idaapi.register_action(ACTION_AR)
idaapi.register_action(ACTION_AP)
idaapi.register_action(ACTION_ER)
idaapi.register_action(ACTION_RR)
idaapi.register_action(ACTION_QQ)

HOOKS = Hooks()
HOOKS.hook()
