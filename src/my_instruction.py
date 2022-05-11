"""
`MyInstruction` module

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""

from iced_x86 import Instruction
from eq_classes_processor import EqClassesProcessor


class MyInstruction:
    """
    `MyInstruction` represents stored instructions with all needed data.
    """
    
    def __init__(self,
                 instr: Instruction,
                 foffset: int,
                 ioffset: int,
                 eq_class: EqClassesProcessor,
                 mov_scheduling_flag: bool = False) -> None:
        """
        Create an instance of `MyInstruction`.
        """
        self.__instr = instr
        self.__foffset = foffset
        self.__ioffset = ioffset
        self.__eq_class = eq_class
        # Store information if MOV instruction is also used for ordering
        # in case that it's also used for substitution (if flag is False
        # and eq_class is set to MOV Scheduling, then only Scheduling
        # is applied).
        # Implicitly False - will be set later on.
        ## This functionality is used only for analysis as combination
        ## of MOV Scheduling with overlapping classes was not implemented
        ## but can be in a future. MOV scheduling with no overlapping
        ## classes was implemented, but this flag is not necessary for it.
        self.__mov_scheduling_flag = mov_scheduling_flag
        
        
    @property
    def instruction(self) -> Instruction:
        """
        Reference to the `Instruction` object, given by `Decoder`
        (`iced_x86`) while disassembling.
        """
        return self.__instr
    
    
    @instruction.setter
    def set_instruction(self, instr: Instruction) -> None:
        self.__instr = instr
        
        
    @property
    def foffset(self) -> int:
        """
        File offset of instruction bytes.
        """
        return self.__foffset
    
    
    @foffset.setter
    def set_foffset(self, foffset: int) -> None:
        self.__foffset = foffset
        
        
    @property
    def ioffset(self) -> int:
        """
        Instruction offset within all decoded instructions (its index).
        """
        return self.__ioffset
    
    
    @ioffset.setter
    def set_ioffset(self, ioffset: int) -> None:
        self.__ioffset = ioffset
        
        
    @property
    def eq_class(self) -> EqClassesProcessor:
        """
        Reference to equivalent class where instruction belongs to.
        """
        return self.__eq_class
    
    
    @eq_class.setter
    def set_eq_class(self, eq_class: EqClassesProcessor) -> None:
        self.__eq_class = eq_class
        
    
    @property
    def mov_scheduling_flag(self) -> bool:
        """
        Flag to say if instruction is MOV belonging to the pair. This flag is used when scheduling MOV also belongs to another class - NOT IMPLEMENTED/USED.
        """
        return self.__mov_scheduling_flag
    
    
    @mov_scheduling_flag.setter
    def set_mov_scheduling_flag(self, flag: bool) -> None:
        self.__mov_scheduling_flag = flag