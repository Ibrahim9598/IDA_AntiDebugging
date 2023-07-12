import idautils 
#import win32gui
from idautils import *
from ctypes import *
from idc import *

antidbg = []

# Checking for the Windows API
# Checking for the IsDebuggerPresent
def IsDebuggerPresent():
    if (windll.kernel32.IsDebuggerPresent()):
        print("Debugger is present, immediatley exit.")

# Checking for the CheckRemoteDebuggerPresent
def RemoteDebuggerPresent():
    if (windll.kernel32.CheckRemoteDebuggerPresent(windll.kernel32.GetCurrentProcess(),False)):
        print("Remote debugger is present, immediatley exit.")

# DEBUGGER DETECTION 
# Check for BeingDebugged flag
def BeingDebugged(ea):
    operand1 = 'dword ptr fs:[30h]'
    operand2 = 'byte ptr [edx+2]'
    operand3 = 1
    if (idc.print_insn_mnem(ea) == 'push') and (operand1 in idc.print_operand(ea,0)):
        if (idc.print_insn_mnem(ea+1) == 'pop') and ("edx" in idc.print_operand(ea+1,1)):
            if(idc.print_insn_mnem(ea+2) == 'cmp') and (operand2 in print_operand(ea + 2, 0))and (operand3 in idc.print_operand(ea+2,1)):          
                antidbg.append(ea)
                print("Check for BeingDebugged flag and is present.")
  
# Check for ProcessHeap Flag
def ProcessHeap(ea):
    operand1 = 'large fs:30h'
    operand2 = 'dword ptr [eax+18h]'
    operand3 = 'dword ptr ds:[eax+10h]'
    operand4 = 0
    if((idc.print_insn_mnem(ea) == 'mov') and ('eax' in idc.print_operand(ea,0)) and (operand1 in idc.print_operand(ea,1))):
        if ((idc.print_insn_mnem(ea+1) == 'mov') and ('eax' in idc.print_operand(ea+1,0)) and (operand2 in idc.print_operand(ea+1,1))):
            if ((idc.print_insn_mnem(ea+2) == 'cmp') and (operand3 in idc.print_operand(ea+2,0)) and (operand4 in idc.print_operand(ea+2,1))):
                antidbg.append(ea)   
                print("Check for ProcessHeap Flag and is present")
        
# Check for NTGlobalFlag
def NTGlobalFlag(ea):
    operand1 = 'large fs:30h'
    operand2 = 'dword ptr ds:[eax+68h]'
    operand3 = 70
    if((idc.print_insn_mnem(ea) == 'mov') and ('eax' in idc.print_operand(ea,0)) and (operand1 in idc.print_operand(ea,1))):
        if((idc.print_insn_mnem(ea+1) == 'cmp') and (operand2 in idc.print_operand(ea+1,0)) and (operand3 in idc.print_operand(ea+1,1))):
            antidbg.append(ea)
            print("Check for NTGlobalFlag Flag and is present")

# Check for System Residue
#def Residue():
    #if (win32gui.FindWindow("OLLYDBG", 0) == None):
      #  print("Debugger Not Found")
    #else:
     #   print("Debugger Detected")
        
# Identifying Debugger Behavior
# check for INT scanning
def INTScanning(ea):
    if print_insn_mnem(ea) == "mov" and "ecx" in print_operand(ea, 0) and "400h" in print_operand(ea, 1):
        if print_insn_mnem(ea + 1) == "mov" and "eax" in print_operand(ea + 1, 0) and "0CCH" in print_operand(ea + 1, 1):
            antidbg.append(ea)
            print("Check for INT scanning and is present")

# check for the rdtsc instruction
def rdtsc():
    if print_insn_mnem(ea) == "rdtsc":
        antidbg.append(ea)
        print("Check for rdtsc flag and is present.")

# Main function

heads = Heads(idc.get_segm_start(get_screen_ea()), idc.get_segm_end(get_screen_ea()))
for ea in heads:    
    IsDebuggerPresent()
    RemoteDebuggerPresent()
    BeingDebugged(ea)
    ProcessHeap(ea)
    NTGlobalFlag(ea)
    INTScanning(ea)
    rdtsc()
    #Residue()

# Print address of antidbg instructions
for i in antidbg:
    ida_kernwin.msg("Anti-Debug: %08x\n" % i)