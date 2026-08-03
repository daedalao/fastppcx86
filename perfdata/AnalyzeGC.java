import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

public class AnalyzeGC extends GhidraScript {
    @Override
    protected void run() throws Exception {
        long[] addresses = {0x18fd13, 0x132b66, 0x0f6a8d, 0x13889f, 0x1208c7, 0x1a361b, 0x11fab1, 0x038850};
        
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        for (long addrVal : addresses) {
            println("\n===========================================");
            println(String.format("Analyzing address: 0x%x", addrVal));
            
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrVal);
            Function func = getFunctionContaining(addr);
            
            if (func == null) {
                println("No function found containing this address.");
                continue;
            }
            
            println("Found function at: " + func.getEntryPoint().toString());
            
            println("\n--- Assembly (first 10 insts) ---");
            Instruction inst = getInstructionAt(func.getEntryPoint());
            int count = 0;
            while (inst != null && count < 10) {
                println(inst.getAddress().toString() + " " + inst.toString());
                inst = inst.getNext();
                count++;
            }
            
            println("\n--- Decompiled Code ---");
            DecompileResults results = ifc.decompileFunction(func, 0, monitor);
            if (results.decompileCompleted()) {
                println(results.getDecompiledFunction().getC());
            } else {
                println("Failed to decompile.");
            }
        }
    }
}
