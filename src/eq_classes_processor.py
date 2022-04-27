import json
import sys
import math


class EqClassesProcessor:
    # List keeps all instantiated equivalent classes.
    all_eq_classes = []
    
    
    def __init__(self,
                 method_name: str,
                 class_name: str,
                 desc: str,
                 members: list,
                 avg_cap: float,
                 min_cap: int,
                 max_cap: int) -> None:
        self.__method_name = method_name
        self.__class_name = class_name
        self.__desc = desc
        self.__members = members
        self.__avg_cap = avg_cap
        self.__min_cap = min_cap
        self.__max_cap = max_cap
        EqClassesProcessor.all_eq_classes.append(self)
    
    
    @property
    def method_name(self) -> str:
        return self.__method_name
        
    
    @property
    def class_name(self) -> str:
        return self.__class_name
        
        
    @property
    def desc(self) -> str:
        return self.__desc
        
        
    @property
    def members(self) -> list:
        return self.__members
    
    
    @property
    def avg_cap(self) -> float:
        return self.__avg_cap
    
        
    @property
    def min_cap(self) -> int:
        return self.__min_cap
        
        
    @property
    def max_cap(self) -> int:
        return self.__max_cap
    
    
    def __repr__(self) -> str:
        mems = ""
        for i in self.members:
            mems += f"{i}, "
        mems = mems[:-2]
        
        return f"\nEqClass('{self.method_name[:10]}...', '{self.class_name}', '{self.desc[:10]}...', [{mems}], {self.avg_cap}, {self.min_cap}, {self.max_cap})"
    
    
    @staticmethod
    def __compute_avg_cap(members: list) -> float:
        # If within one Equivalent Class is number of members not equal
        # to Power of 2, then only average capacity can be computed as
        # real capacity depend on exact occurence of particular members
        # from class.
        n = len(members)
        return math.ceil(math.log2(n)-1) + \
            (n - pow(2, math.ceil(math.log2(n) - 1))) / \
                (pow(2, math.ceil(math.log2(n) - 1)))
    
    
    @classmethod
    def prepare_eq_classes(cls, method: str, fconfig: str) -> None:
        
        try:
            fd = open(fconfig, "r")
        except IOError:
            print(f"ERROR! Can not load configuration file: {fconfig}", file=sys.stderr)
            sys.exit(101)
        
        obj_json = json.load(fd)
        fd.close()
        
        # Change form of string method.
        if method == "mov":
            method = "Scheduling"
        elif method == "nops":
            method = "NOP Instructions Using"
        elif method == "sub":
            method = "Basic Instruction Substitution"
        elif method == "ext-sub":
            method = "Extended Instruction Substitution"
        
        for method_name in obj_json:
            
            obj_eq_classes = obj_json[method_name]
            # Load only equivalent classes appropriate for given method,
            # also when 'ext-sub' method is given, classes for 'sub'
            # method are loaded as well.
            if method_name == method or \
                (
                    method == "Extended Instruction Substitution" and \
                    method_name == "Basic Instruction Substitution"
                ) or method == "ext-sub-nops-mov":
                
                for eq_class_name in obj_eq_classes:
                    
                    obj_eq_class = obj_eq_classes[eq_class_name]
                    
                    # Compute capacities for some equivalent classes.
                    if eq_class_name == ">3 Bytes Long NOP":
                        # This must be computed for every instruction
                        # separately, therefore 0 for now.
                        cap = 0.0
                        
                    elif eq_class_name == "MOV Scheduling" or \
                        eq_class_name == "Swap base-index registers":
                        cap = 1.0
                    
                    else:
                        cap = cls.__compute_avg_cap(obj_eq_class['Members'])
                    
                    cls(
                        method_name=method_name,
                        class_name=eq_class_name,
                        desc=obj_eq_class['Description'],
                        members=obj_eq_class['Members'],
                        avg_cap=cap,
                        min_cap=math.floor(cap),
                        max_cap=math.ceil(cap),
                    )