#----------------------------------------------------------------------------
# angr plug-in for IDA Pro
#
#
#
#----------------------------------------------------------------------------
from __future__ import print_function
import idaapi, angr


findAddrs = []
avoidAddrs = []

def hotkey_pressed_find():
	try:
		addr = idaapi.get_screen_ea()
		if addr in findAddrs:
			findAddrs.remove(addr)
			SetColor(here(), CIC_ITEM, 0xffffff)
			print("IDA~ANGR: Removed find address [%s]" % hex(addr))
		else:
			if addr in avoidAddrs:
				avoidAddrs.remove(addr)
			findAddrs.append(addr)
			SetColor(here(), CIC_ITEM, 0x208020)
			print("IDA~ANGR: Added find address [%s]" % hex(addr))
	except:
		print("IDA~ANGR:\n*** FAILED TO HANDLE FIND ADDRESS ***\n") 

def hotkey_pressed_avoid():
	try:
		addr = idaapi.get_screen_ea()
		if addr in avoidAddrs:
			avoidAddrs.remove(addr)
			SetColor(here(), CIC_ITEM, 0xffffff)
			print("IDA~ANGR: Removed avoid address [%s]" % hex(addr))
		else:
			if addr in findAddrs:
				findAddrs.remove(addr)
			avoidAddrs.append(addr)
			SetColor(here(), CIC_ITEM, 0x2020c0)
			print("IDA~ANGR: Added avoid address [%s]" % hex(addr))
	except:
		print("IDA~ANGR:\n*** FAILED TO HANDLE AVOID ADDRESS ***\n") 


def hotkey_pressed_view():
	try:
		print("IDA~ANGR:\n\tFind Addresses")
		for addr in findAddrs:
			print("\t\t%s" % hex(addr))

		print("\tAvoid Addresses")
		for addr in avoidAddrs:
			print("\t\t%s" % hex(addr))
		
	except:
		print("IDA~ANGR:\n*** FAILED TO VIEW VARIABLES ***\n") 
		
def hotkey_pressed_refresh():
	try:
		for addr in findAddrs:
			SetColor(addr, CIC_ITEM, 0xffffff)
			findAddrs.remove(addr)
			
		for addr in avoidAddrs:
			SetColor(addr, CIC_ITEM, 0xffffff)
			avoidAddrs.remove(addr)

		print("IDA~ANGR: Refresh completed.")

	except:
		print("IDA~ANGR:\n*** FAILED TO REFRESH ***\n")


def hotkey_pressed_explore():
	print("Hotkey explore has been pressed!")
	file = idaapi.get_input_file_path()
	print(file)
	proj = angr.Project(file,  load_options={"auto_load_libs":False})
	initial_state = proj.factory.entry_state() 
	initial_state.options.discard("LAZY_SOLVES")

	for _ in range(0,32):
		k = initial_state.posix.files[0].read_from(1)
		initial_state.se.add(k != 0)
		initial_state.se.add(k != 10)

	# The last char of user input must be a newline
	k = initial_state.posix.files[0].read_from(1)
	initial_state.se.add(k == 10)

	# Reset the stdin to the beginning, 0
	initial_state.posix.files[0].seek(0)
	initial_state.posix.files[0].length = 33

	pg = proj.factory.path_group(initial_state, immutable=False)
	pg.explore(find=findAddrs, avoid=avoidAddrs)

	found = pg.found[0].state
	found.posix.files[0].seek(0)
	print("Found: "+ found.se.any_str(found.posix.files[0].read_from(33)))




try: 
	hotkey_find	
	if idaapi.del_hotkey(hotkey_find):
		print("Hotkey find unregistered!")
		del hotkey_find
	else:
		print("Failed to delete hotkey find!")

	hotkey_avoid	
	if idaapi.del_hotkey(hotkey_avoid):
		print("Hotkey avoid unregistered!")
		del hotkey_avoid
	else:
		print("Failed to delete hotkey avoid!")

	hotkey_view
	if idaapi.del_hotkey(hotkey_view):
		print("Hotkey view unregistered!")
		del hotkey_view
	else:
		print("Failed to delete hotkey view!")

	hotkey_refresh
	if idaapi.del_hotkey(hotkey_refresh):
		print("Hotkey refresh unregistered!")
		del hotkey_refresh
	else:
		print("Failed to delete hotkey refresh!")

	hotkey_explore
	if idaapi.del_hotkey(hotkey_explore):
		print("Hotkey explore unregistered!")
		del hotkey_explore
	else:
		print("Failed to delete hotkey explore!")

except:
	hotkey_find = idaapi.add_hotkey("Ctrl-Shift-f", hotkey_pressed_find)
	if hotkey_find is None:
		print("Failed to register hotkey_find!")
		del hotkey_find
	else:
		print("Hotkey_find registered! Ctrl-Shift-F")

	hotkey_avoid = idaapi.add_hotkey("Ctrl-Shift-a", hotkey_pressed_avoid)
	if hotkey_avoid is None:
		print("Failed to register hotkey_avoid!")
		del hotkey_avoid
	else:
		print("hotkey_avoid registered! Ctrl-Shift-A")

	hotkey_view = idaapi.add_hotkey("Ctrl-Shift-v", hotkey_pressed_view)
	if hotkey_view is None:
		print("Failed to register hotkey_view!")
		del hotkey_view
	else:
		print("hotkey_view registered! Ctrl-Shift-V")

	hotkey_refresh = idaapi.add_hotkey("Ctrl-Shift-r", hotkey_pressed_refresh)
	if hotkey_refresh is None:
		print("Failed to register hotkey_refresh!")
		del hotkey_refresh
	else:
		print("hotkey_refresh registered! Ctrl-Shift-R")

	hotkey_explore = idaapi.add_hotkey("Ctrl-Shift-e", hotkey_pressed_explore)
	if hotkey_explore is None:
		print("Failed to register hotkey_explore!")
		del hotkey_explore
	else:
		print("hotkey_explore registered! Ctrl-Shift-E")