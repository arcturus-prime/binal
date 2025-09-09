import json
import binaryninja

from binaryninja.types import Type

filename = binaryninja.interaction.get_open_filename_input("Apply dump")

if filename:
    with open(filename, "r") as file:
        json_string = file.read()
        json_object = json.loads(json_string)
        file.close()
else:
    exit()

def lift_primitive_type(type_):
    kind = type_["info"]["kind"]

    if kind == "uint":
        return Type.int(type_["size"], False)
    elif kind == "int":
        return Type.int(type_["size"], True)
    elif kind == "float":
        return Type.float(type_["size"])
    elif kind == "bool":
        return Type.bool()
    elif kind == "pointer":
        to_type_id = type_["info"]["value_type"]
        to_type = json_object["types"][to_type_id]
    
        name = to_type.get("name")

        binja_type = bv.types.get(name) if name != None else None
        binja_type = binja_type or lift_primitive_type(to_type)
        if not binja_type:
            to_parse.append(to_type)
            return None

        return Type.pointer_of_width(type_["size"], binja_type)
    elif kind == "array":
        item_type_id = type_["info"]["item_type"]
        item_type = json_object["types"][item_type_id]

        name = item_type.get("name")

        binja_type = bv.types.get(name) if name != None else None
        binja_type = binja_type or lift_primitive_type(item_type)
        if not binja_type:
            to_parse.append(item_type)
            return None

        return Type.array(binja_type, int(type_["size"] / item_type["size"]))
    elif kind == "function":
        return None

    return None

print("Applying types...")

to_parse = binaryninja.collections.deque()
for id_, type_ in json_object["types"].items():
    if type_["info"]["kind"] in "uint int float pointer bool array unknown function":
        continue

    to_parse.append(type_)

while to_parse:
    type_ = to_parse.popleft()

    kind = type_["info"]["kind"]
    if kind == "struct":
        fields = type_["info"]["fields"]
        binja_type = binaryninja.StructureBuilder.create()

        cannot_yet_parse = False
        for field in fields:
            field_type = json_object["types"][field["field_type"]]
            field_type_name = field_type["info"].get("name")

            binja_field = bv.types.get(field_type_name) if field_type_name != None else None
            binja_field = binja_field or lift_primitive_type(field_type)

            if binja_field is None:
                to_parse.append(field_type)
                cannot_yet_parse = True
                continue

            binja_type.add_member_at_offset(field["name"], binja_field, field["offset"])

        if cannot_yet_parse:
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["info"]["name"], binja_type)
    elif kind == "enum":
        values = type_["info"]["values"]
        
        binja_type = binaryninja.EnumerationBuilder.create()
        for value in values:
            binja_type.append(value["name"], value["value"])

        bv.define_user_type(type_["info"]["name"], binja_type)
    elif kind == "union":
        fields = type_["info"]["fields"]
        binja_type = binaryninja.TypeBuilder.union()

        cannot_yet_parse = False
        for field in fields:
            field_type = json_object["types"][field["field_type"]]
            field_type_name = field_type["info"].get("name")

            binja_field = bv.types.get(field_type_name) if field_type_name != None else None
            binja_field = binja_field or lift_primitive_type(field_type)

            if binja_field is None:
                to_parse.append(field_type)
                cannot_yet_parse = True
                continue

            binja_type.append(binja_field, field["name"])

        if cannot_yet_parse:
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["info"]["name"], binja_type)
    elif kind == "typedef":
        to_type_id = type_["info"]["alias_type"]
        to_type = json_object["types"][to_type_id]

        to_type_name = to_type["info"].get("name")

        binja_type = bv.types.get(to_type_name) if to_type_name != None else None
        binja_type = binja_type or lift_primitive_type(to_type)

        if binja_type is None:
            to_parse.append(to_type)
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["info"]["name"], binja_type)
    else:
        continue

print("Done")
print("Applying functions...")
for id_, function_ in json_object["functions"].items():
    f = bv.create_user_function(int(function_["location"]))

    json_return_type = json_object["types"][function_["return_type"]]
    return_type = bv.types.get(json_return_type["name"]) or lift_primitive_type(json_return_type)

    params = []
    for param in json_return_type["arguments"]:
        json_param_type = json_object["types"][param["arg_type"]]

        param_type = bv.types.get(json_param_type["name"]) or lift_primitive_type(json_param_type)
        params.append(param_type)

    f.type = binaryninja.FunctionType.create(return_type, params)

print("Done")
