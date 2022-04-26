import json
import sys


class EqClassesProcessor:
    # List keeps all instantiated equivalent classes.
    all_eq_classes = []
    
    
    def __init__(self, name: str, desc: str, members: list) -> None:
        self.__name = name
        self.__desc = desc
        self.__members = members
        EqClassesProcessor.all_eq_classes.append(self)
    
    
    def __repr__(self) -> str:
        mems = ""
        for i in self.__members:
            mems += f"{i}, "
        mems = mems[:-2]
        
        return f"\nEqClass('{self.__name}', '{self.__desc[:10]}...', [{mems}])"
    
    
    @classmethod
    def prepare_eq_classes(cls) -> None:
        try:
            fd = open("./substitution-classes.json", "r")
        except IOError:
            print(f"ERROR! Can not load configuration file: ", file=sys.stderr)
            sys.exit(101)
        
        json_obj = json.load(fd)
        fd.close()
        
        # if method == "ext-sub-nops":
        #     pass
        
        # if method == "nops" or \
        #     method == "nops-embedding":
            
        #     i = 0
            
        # elif method == "ext-sub" or \
        #     method == "extended-substitution":
            
        #     i = 1    
            
        # elif method == "sub" or \
        #     method == "instruction-substitution":
                
        #     i = 2
        
        for method_data in json_obj:
            for eq_classes in method_data['Classes']:
                cls(
                    name=eq_classes['Name'],
                    desc=eq_classes['Description'],
                    members=eq_classes['Members']
                )