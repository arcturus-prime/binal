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

print("Applying types...")
parsed_types = {}
to_parse = binaryninja.collections.deque()
for id_, type_ in json_object["types"].items():
    to_parse.append((id_, type_))

while to_parse:
    id_, type_ = to_parse.popleft()

    kind = type_["info"]["kind"]

    if kind == "struct":
        fields = type_["info"]["fields"]
        binja_type = binaryninja.StructureBuilder.create()

        cannot_yet_parse = False
        for field in fields:
            field_type_id = field["field_type"]
            field_type = json_object["types"][field_type_id]

            if parsed_types.get(field_type_id) is None:
                cannot_yet_parse = True
                break

            binja_type.add_member_at_offset(field["name"], parsed_types[field_type_id], field["offset"])

        if cannot_yet_parse:
            to_parse.append((id_, type_))
            continue

        parsed_types[id_] = binja_type
    elif kind == "uint":
        parsed_types[id_] = Type.int(type_["size"], False)
    elif kind == "int":
        parsed_types[id_] = Type.int(type_["size"], True)
    elif kind == "float":
        parsed_types[id_] = Type.float(type_["size"])
    elif kind == "bool":
        parsed_types[id_]if kind == "struct":
        fields = type_["info"]["fields"]
        binja_type = binaryninja.StructureBuilder.create()

        cannot_yet_parse = False
        for field in fields:
            field_type_id = field["field_type"]
            field_type = json_object["types"][field_type_id]

            if parsed_types.get(field_type_id) is None:
                cannot_yet_parse = True
                break

            binja_type.add_member_at_offset(field["name"], parsed_types[field_type_id], field["offset"])

        if cannot_yet_parse:
            to_parse.append((id_, type_))
            continue

        parsed_types[id_] = binja_type
    elif kind == "uint":
        parsed_types[id_] = Type.int(type_["size"], False)
    elif kind == "int":
        parsed_types[id_] = Type.int(type_["size"], True)
    elif kind == "float":
        parsed_types[id_] = Type.float(type_["size"])
    elif kind == "bool":
        parsed_types[id_]  = Type.bool()
    elif kind == "function":
        args = type_["info"]["arg_types"]
        return_type = type_["info"]["return_type"]

        parsed_types[id_] = Type.void()
    elif kind == "pointer":
        to_type_id = type_["info"]["value_type"]
        to_type = json_object["types"][to_type_id]

        if parsed_types.get(to_type_id) is None:
            to_parse.append((id_, type_))
            continue

        parsed_types[id_] = Type.pointer_of_width(type_["size"], parsed_types[to_type_id])
    elif kind == "array":
        item_type_id = type_["info"]["item_type"]
        item_type = json_object["types"][item_type_id]

        if parsed_types.get(item_type_id) is None:
            to_parse.append((id_, type_))
            continue

        parsed_types[id_] = Type.array(parsed_types[item_type_id], int(type_["size"] / item_type["size"]))
    elif kind == "enum":
        values = type_["info"]["values"]
        
        binja_type = binaryninja.EnumerationBuilder.create()
        for value in values:
            binja_type.append(value["name"], value["value"])

        parsed_types[id_] = binja_type
    elif kind == "union":
        fields = type_["info"]["fields"]
        binja_type = binaryninja.TypeBuilder.union()

        cannot_yet_parse = False
        for field in fields:
            field_type_id = field["field_type"]
            field_type = json_object["types"][field_type_id]

            if parsed_types.get(field_type_id) is None:
                cannot_yet_parse = True
                break

            binja_type.append(parsed_types[field_type_id], field["name"])

        if cannot_yet_parse:
            to_parse.append((id_, type_))
            continue

        parsed_types[id_] = binja_type
    elif kind == "typedef":
        to_type_id = type_["info"]["alias_type"]
        to_type = json_object["types"][to_type_id]

        if parsed_types.get(to_type_id) is None:
            to_parse.append((id_, type_))

            bv.define_user_type(type_["info"]["name"], Type.void())
            parsed_types[id_] = Type.named_type_from_registered_type(bv, type_["info"]["name"])
            continue

        bv.define_user_type(type_["info"]["name"], parsed_types[to_type_id])
        parsed_types[id_] = Type.named_type_from_registered_type(bv, type_["info"]["name"])
    elif kind == "unknown":
        parsed_types[id_] = Type.void()
    else:
        print("Unhandled type", type_)
        continue

print("Done")
print("Applying functions...")
for id_, function_ in json_object["functions"].items():
    f = bv.create_user_function(int(function_["location"]))

    json_return_type = json_object["types"][function_["return_type"]]
    return_type = bv.types.get(json_return_type["name"]) 

    params = []
    for param in json_return_type["arguments"]:
        json_param_type = json_object["types"][param["arg_type"]]

        param_type = bv.types.get(json_param_type["name"])
        params.append(param_type)

    f.type = binaryninja.FunctionType.create(return_type, params)

print("Done")
