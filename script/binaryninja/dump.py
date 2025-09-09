import json
import hashlib

from binaryninja import (
    DataVariable,
    TypeClass,
    Type,
    collections,
)
import binaryninja

def hash_string(s: str):
    return str(int(hashlib.sha1(s.encode("utf-8")).hexdigest(), 16) % (10 ** 8))

def get_pointer_info(type_):
    depth = 0
    while type_.type_class == TypeClass.PointerTypeClass:
        type_ = type_.target
        depth += 1

    return type_, depth

print("Lifting types...")
types = {}
to_parse = collections.deque()
for type_ in bv.types.values():
    to_parse.append(type_)

parsed_types = set({})
while to_parse:
    type_ = to_parse.popleft()

    # need to do this to prevent circular type traversal
    if type_ in parsed_types:
        continue

    parsed_types.add(type_)

    binal_type = {"size": type_.width, "alignment": type_.alignment }
    
    if type_.type_class == TypeClass.PointerTypeClass:
        binal_type["info"] = { "kind": "pointer" }

        ptr_base_type, binal_type["info"]["depth"] = get_pointer_info(type_);
        binal_type["info"]["value_type"] = hash_string(ptr_base_type.get_string())

        to_parse.append(ptr_base_type)
    elif type_.type_class == TypeClass.IntegerTypeClass:
        binal_type["info"] = { "kind": "int" if type_.signed else "uint" } 
    elif type_.type_class == TypeClass.BoolTypeClass:
        binal_type["info"] = { "kind": "bool" }
    elif type_.type_class == TypeClass.FloatTypeClass:
        binal_type["info"] = { "kind": "float" }
    elif type_.type_class == TypeClass.EnumerationTypeClass:
        binal_type["info"] = { "kind": "enum", "values": [], "name": type_.get_string() }
        
        for member in type_.members:
            binal_type["info"]["values"].append({
                "name": member.name,
                "value": member.value
            })

    elif type_.type_class == TypeClass.StructureTypeClass:
        binal_type["info"] = { "kind": "struct", "fields": [], "name": type_.get_string() }
   
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

        to_parse.append(type_.return_value)
    elif type_.type_class == TypeClass.ArrayTypeClass:
        to_parse.append(type_.element_type)
        binal_type["info"] = { "kind": "array", "item_type": hash_string(type_.element_type.get_string()) }
    elif type_.type_class == TypeClass.NamedTypeReferenceClass and type_.target(bv) != None:
        to_parse.append(type_.target(bv))            
        binal_type["info"] = { "kind": "typedef", "alias_type": hash_string(type_.target(bv).get_string()), "name": type_.get_string() }
    elif type_.type_class == TypeClass.NamedTypeReferenceClass:
        binal_type["info"] = { "kind": "unknown" }
    elif type_.type_class == TypeClass.WideCharTypeClass:
        binal_type["info"] = { "kind": "uint" }
    else:
        # any other types shouldn't be sent either
        continue

    types[hash_string(type_.get_string())] = binal_type

print("Done.")
print("Lifting data variables...")
data = {}
for data_var in bv.data_vars.values():
    name = hash_string(data_var.name) if data_var.name != None else str(data_var.address)
    binal_globals = { name:  { "kind": "data", "name": data_var.name, "location": data_var.address, "data_type": hash_string(data_var.type.get_string()) } }

print("Done.")
print("Lifting functions...")
functions = {}
for function in bv.functions:
    arguments = []
    for parameter in function.type.parameters:
        arguments.append(
            {"name": parameter.name, "arg_type": hash_string(parameter.type.get_string())}
        )
    
    binal_func = {
        "location": function.start,
        "return_type": hash_string(function.return_type.get_string()),
        "arguments": arguments,
        "name": function.name
    }

    functions[hash_string(function.name)] = binal_func

print("Done")

filename = binaryninja.interaction.get_save_filename_input("Save dump")
json_string = json.dumps({ "types": types, "functions": functions, "data": data })

if filename:
    with open(filename, "w") as file:
        file.write(json_string)
        file.close()

