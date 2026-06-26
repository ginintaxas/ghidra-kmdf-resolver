# @ginintaxas
# @category KMDF
try:
    _ = currentProgram
except:
    from ghidra.ghidra_builtins import *

from ghidra import *
from ghidra.app.decompiler import DecompInterface
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.data import (
    DataTypeConflictHandler,
    DataUtilities,
    PointerDataType,
)
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType, ThunkReference
from ghidra.util.task import ConsoleTaskMonitor

listing = currentProgram.getListing()
dtm = currentProgram.getDataTypeManager()
ref_manager = currentProgram.getReferenceManager()
symbolTable = currentProgram.getSymbolTable()
decompIntr = DecompInterface()


# return address of the call to wdf version bind
def get_vb_ref():
    function_name = "WdfVersionBind"
    symbols = symbolTable.getSymbols(function_name)
    if symbols.hasNext():
        sym = symbols.next()
    if len(list(symbols)) > 1:
        raise ValueError(
            f"There can only be one of the external symbol {function_name}"
        )
    for ref in sym.getReferences():
        if ref.getReferenceType().isCall() or isinstance(ref, ThunkReference):
            thunk_addr = ref.getFromAddress()
    for ref in ref_manager.getReferencesTo(thunk_addr):
        if ref.getReferenceType().isCall():
            return ref
    return None


def get_arg_lea_instr(cur_instr, arg_reg_name):
    for instr_count in range(30):
        mnemonic = cur_instr.getMnemonicString()
        if mnemonic in ["MOV", "LEA"]:
            dest_reg = cur_instr.getRegister(0)
            if dest_reg.getName().upper() == arg_reg_name:
                break
        cur_instr = cur_instr.getPrevious()
    if instr_count == 29:
        return None
    return cur_instr


def rename_globals(call_addr):
    cur_instr = listing.getInstructionAt(call_addr)
    cur_instr = get_arg_lea_instr(cur_instr, "R9")
    wdf_globas_sym = cur_instr.getPrimaryReference(1)
    if wdf_globas_sym is not None:
        global_addr = wdf_globas_sym.getToAddress()
        symbol = symbolTable.getPrimarySymbol(global_addr)
        if symbol is not None:
            print(symbol.getName())
            symbol.setName("WDF_GLOBALS", SourceType.USER_DEFINED)
    return


def find_wdf_bind_info_addr(vb_addr):
    rename_globals(vb_addr)
    addr = None
    cur_instr = listing.getInstructionAt(vb_addr)
    cur_instr = get_arg_lea_instr(cur_instr, "R8")
    wdf_bind_addr = cur_instr.getPrimaryReference(1).getToAddress()
    return wdf_bind_addr


def extract_wdffunc_ptr(bind_info_addr):
    print(f"found wdf bind info address: {bind_info_addr}")
    service = state.getTool().getService(DataTypeManagerService)
    all_managers = service.getDataTypeManagers()
    for mgr in all_managers:
        for dt in mgr.getAllDataTypes():
            if dt.getName() == "WDF_BIND_INFO":
                data = listing.getDataAt(bind_info_addr)
                current_type_name = data.getDataType().getName()
                if not "WDF_BIND_INFO" in current_type_name:
                    listing.clearCodeUnits(
                        bind_info_addr, bind_info_addr.add(dt.getLength() - 1), True
                    )
                    data = listing.createData(bind_info_addr, dt)

                # wdf_bind_info offset for func table ptr is 0x20
                func_tbl_ptr_data = data.getComponentContaining(0x20)
                if func_tbl_ptr_data.isPointer():
                    return func_tbl_ptr_data.getValue()
                else:
                    raise ValueError("Couldnt extract the function table pointer value")
    raise ValueError("WDF_BIND_INFO not found, did you import the correct data types?")


def get_wdffunc_addr():
    vb_call_addr = get_vb_ref().getFromAddress()
    bind_info = find_wdf_bind_info_addr(vb_call_addr)
    func_table_addr = extract_wdffunc_ptr(bind_info)
    return func_table_addr


def resolve_func_addrs(tableptr_address):
    service = state.getTool().getService(DataTypeManagerService)
    all_managers = service.getDataTypeManagers()
    for mgr in all_managers:
        for dt in mgr.getAllDataTypes():
            if dt.getName() == "WDFFUNCTIONS":
                data = listing.getDataAt(tableptr_address)
                current_type_name = data.getDataType().getName()
                if not "WDFFUNCTIONS *" in current_type_name:
                    listing.clearCodeUnits(
                        tableptr_address, tableptr_address.add(7), True
                    )
                    func_ptr_type = PointerDataType(dt, dtm)
                    listing.createData(tableptr_address, func_ptr_type)
                return
    raise ValueError("WDFFUNCTIONS not found, did you import the correct data types?")


if __name__ == "__main__":
    print("resolving function names")
    tblptr_addr = get_wdffunc_addr()
    print(f"found function table address: {tblptr_addr}")
    resolve_func_addrs(tblptr_addr)
