from iced_x86 import Instruction
from eq_classes_processor import EqClassesProcessor


class MyInstruction:
    
    
    def __init__(self,
                 instr: Instruction,
                 foffset: int,
                 ioffset: int,
                 eq_class: EqClassesProcessor,
                 mov_scheduling_flag: bool = False) -> None:
        self.__instr = instr
        self.__foffset = foffset
        self.__ioffset = ioffset
        self.__eq_class = eq_class
        # Store information if MOV instruction is also used for ordering
        # in case that it's also used for substitution (if flag is False
        # and eq_class is set to MOV Scheduling, then only Scheduling
        # is applied).
        # Implicitly False - will be set later on.
        self.__mov_scheduling_flag = mov_scheduling_flag
        
        
    @property
    def instruction(self) -> Instruction:
        return self.__instr
    
    
    @instruction.setter
    def set_instruction(self, instr: Instruction) -> None:
        self.__instr = instr
        
        
    @property
    def foffset(self) -> int:
        return self.__foffset
    
    
    @foffset.setter
    def set_foffset(self, foffset: int) -> None:
        self.__foffset = foffset
        
        
    @property
    def ioffset(self) -> int:
        return self.__ioffset
    
    
    @ioffset.setter
    def set_ioffset(self, ioffset: int) -> None:
        self.__ioffset = ioffset
        
        
    @property
    def eq_class(self) -> EqClassesProcessor:
        return self.__eq_class
    
    
    @eq_class.setter
    def set_eq_class(self, eq_class: EqClassesProcessor) -> None:
        self.__eq_class = eq_class
        
    
    @property
    def mov_scheduling_flag(self) -> bool:
        return self.__mov_scheduling_flag
    
    
    @mov_scheduling_flag.setter
    def set_mov_scheduling_flag(self, flag: bool) -> None:
        self.__mov_scheduling_flag = flag