import json
import hashlib

from binaryninja import (
    DataVariable,
    TypeClass,
    Type,
)
import binaryninja

def hash_string(s: str):
    return str(int(hashlib.sha1(s.encode("utf-8")).hexdigest(), 16) % (10 ** 6))

def lift_function(func):
    binal_functions = {}
    binal_types = {}

    arguments = []
    for parameter in func.type.parameters:
        arguments.append(
            {"name": parameter.name, "arg_type": hash_string(parameter.type.get_string())}
        )

        binal_types.update(lift_type(parameter.type))
    
    binal_func = {
        "location": func.start,
        "return_type": hash_string(func.return_type.get_string()),
        "arguments": arguments,
        "name": func.name
    }

    binal_functions[hash_string(func.name)] = binal_func

    return binal_functions, binal_types

def get_pointer_info(type_):
    depth = 0
    while type_.type_class == TypeClass.PointerTypeClass:
        type_ = type_.target
        depth += 1

    return type_, depth

def lift_type(type_: Type):
    binal_types = {}

    # array where we can push dependent types that we encounter
    to_parse = [type_]
    parsed_types = set({})

    while to_parse:
        type_ = to_parse.pop()

        # need to do this to prevent circular type traversal
        if type_ in parsed_types:
            continue

        parsed_types.add(type_)

        binal_type = {"size": type_.width, "alignment": type_.alignment, "name": type_.get_string() }
        
        if type_.type_class == TypeClass.PointerTypeClass:
            binal_type["info"] = { "kind": "pointer" }

            ptr_base_type, binal_type["info"]["depth"] = get_pointer_info(type_);
            binal_type["info"]["value_type"] = hash_string(ptr_base_type.get_string())

            if hash_string(ptr_base_type.get_string()) == "793658":
                print(ptr_base_type)

            to_parse.append(ptr_base_type)
        elif type_.type_class == TypeClass.IntegerTypeClass:
            binal_type["info"] = { "kind": "int" if type_.signed else "uint" } 
        elif type_.type_class == TypeClass.BoolTypeClass:
            binal_type["info"] = { "kind": "bool" }
        elif type_.type_class == TypeClass.FloatTypeClass:
            binal_type["info"] = { "kind": "float" }
        elif type_.type_class == TypeClass.EnumerationTypeClass:
            binal_type["info"] = { "kind": "enum", "values": [] }
            
            for member in type_.members:
                binal_type["info"]["values"].append({
                    "name": member.name,
                    "value": member.value
                })

        elif type_.type_class == TypeClass.StructureTypeClass:
            binal_type["info"] = { "kind": "struct", "fields": [] }
       
            for field in type_.members:
                to_parse.append(field.type)
    
                binal_type["info"]["fields"].append({
                    "name": field.name,
                    "offset": field.offset,
                    "field_type": hash_string(field.type.get_string())
                })

        elif type_.type_class == TypeClass.VoidTypeClass:
            binal_type["info"] = { "kind": "uint" }
        elif type_.type_class == TypeClass.FunctionTypeClass:
            binal_type["info"] = { "kind": "function", "return_type": hash_string(type_.return_value.get_string()), "arg_types": []}

            for argument in type_.parameters:
                binal_type["info"]["arg_types"].append(hash_string(argument.type.get_string()))
                to_parse.append(argument.type)

        elif type_.type_class == TypeClass.ArrayTypeClass:
            to_parse.append(type_.element_type)
            binal_type["info"] = { "kind": "array", "item_type": hash_string(type_.element_type.get_string()) }
        elif type_.type_class == TypeClass.NamedTypeReferenceClass and type_.target(bv):
            to_parse.append(type_.target(bv))
            binal_type["info"] = { "kind": "typedef", "alias_type": hash_string(type_.target(bv).get_string()) }
        elif type_.type_class == TypeClass.WideCharTypeClass:
            binal_type["info"] = { "kind": "uint" }
        elif type_.type_classq == TypeClass.ValueTypeClass
        else:
            # any other types shouldn't be sent either
            continue

        binal_types[hash_string(type_.get_string())] = binal_type

    return binal_types

def lift_data(data_: DataVariable):
    binal_types = lift_type(data_.type)

    name = hash_string(data_.name) if data_.name != None else str(data_.address)
    binal_globals = { name:  { "kind": "data", "name": data_.name, "location": data_.address, "data_type": hash_string(data_.type.get_string()) } }

    return binal_globals, binal_types


print("Lifting types...")
types = {}
for type_ in bv.types.values():
    types.update(lift_type(type_))

print("Done.")
print("Lifting data variables...")
data = {}
for data_var in bv.data_vars.values():
    binal_datas, binal_types = lift_data(data_var)
    types.update(binal_types)
    data.update(binal_datas)

print("Done.")
print("Lifting functions...")
functions = {}
for function in bv.functions:
    binal_functions, binal_types = lift_function(function)
    functions.update(binal_functions)
    types.update(binal_types)

filename = binaryninja.interaction.get_save_filename_input("Save dump")
json_string = json.dumps({ "types": types, "functions": functions, "data": data })

if filename:
    with open(filename, "w") as file:
        file.write(json_string)
        file.close()

