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
    def prepare_eq_classes(cls, method: str, fconfig: str) -> None:
        
        print(fconfig)
        try:
            fd = open(fconfig, "r")
        except IOError:
            print(f"ERROR! Can not load configuration file: {fconfig}", file=sys.stderr)
            sys.exit(101)
        
        json_obj = json.load(fd)
        fd.close()
        
        for method_data in json_obj:
            if method == method_data['Method'] or \
                (
                    method == "ext-sub" and method_data['Method'] == "sub"
                ) or \
                method == "ext-sub-nops-mov":
                for eq_classes in method_data['Classes']:
                    cls(
                        name=eq_classes['Name'],
                        desc=eq_classes['Description'],
                        members=eq_classes['Members']
                    )