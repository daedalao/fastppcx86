import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address

addresses = [0x18fd13, 0x132b66, 0x0f6a8d, 0x13889f, 0x1208c7, 0x1a361b, 0x11fab1, 0x038850]

monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(currentProgram)

for addr_val in addresses:
    print("\n===========================================")
    print("Analyzing address: 0x%x" % addr_val)
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
    func = getFunctionContaining(addr)
    
    if func is None:
        print("No function found containing this address.")
        continue
        
    print("Found function at: %s" % func.getEntryPoint())
    
    # Print first 10 instructions
    print("\n--- Assembly (first 10 insts) ---")
    inst = getInstructionAt(func.getEntryPoint())
    count = 0
    while inst is not None and count < 10:
        print("%s %s" % (inst.getAddress(), inst))
        inst = inst.getNext()
        count += 1
        
    # Decompile
    print("\n--- Decompiled Code ---")
    results = ifc.decompileFunction(func, 0, monitor)
    if results.decompileCompleted():
        print(results.getDecompiledFunction().getC())
    else:
        print("Failed to decompile.")
