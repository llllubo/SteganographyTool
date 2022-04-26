import json
import sys


class EqClassesProcessor:
    # List keeps all instantiated equivalent classes.
    all_eq_classes = []
    
    
    def __init__(self,
                 method_name: str,
                 class_name: str,
                 desc: str,
                 members: list) -> None:
        self.__method_name = method_name
        self.__class_name = class_name
        self.__desc = desc
        self.__members = members
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
    
    
    def __repr__(self) -> str:
        mems = ""
        for i in self.members:
            mems += f"{i}, "
        mems = mems[:-2]
        
        return f"\nEqClass('{self.method_name[:10]}...', '{self.class_name}', '{self.desc[:10]}...', [{mems}])"
    
    
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
        if method == "nops":
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
                    cls(
                        method_name=method_name,
                        class_name=eq_class_name,
                        desc=obj_eq_class['Description'],
                        members=obj_eq_class['Members']
                    )