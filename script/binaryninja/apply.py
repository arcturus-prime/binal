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

to_parse = binaryninja.collections.deque()
for id_, type_ in json_object["types"].items():
    if type_["info"]["kind"] in "uint int float pointer bool array":
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

            binja_field = bv.types.get(field_type["name"])

            if not binja_field:
                to_parse.append(field_type)
                cannot_yet_parse = True
                continue

            binja_type.add_member_at_offset(field["name"], binja_field, field["offset"])

        if cannot_yet_parse:
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["name"], binja_type)
    elif kind == "enum":
        values = type_["info"]["values"]
        
        binja_type = binaryninja.EnumerationBuilder.create()
        for value in values:
            binja_type.append(value["name"], value["value"])

        bv.define_user_type(type_["name"], binja_type)
    elif kind == "union":
        fields = type_["info"]["fields"]
        binja_type = binaryninja.TypeBuilder.union()

        cannot_yet_parse = False
        for field in fields:
            field_type = json_object["types"][field["field_type"]]
            binja_field = bv.types.get(field_type["name"])

            if not binja_field:
                to_parse.append(field_type)
                cannot_yet_parse = True
                continue

            binja_type.append(binja_field, field["name"])

        if cannot_yet_parse:
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["name"], binja_type)
    elif kind == "uint":
        bv.define_user_type(type_["name"], Type.int(type_["size"], False))
    elif kind == "int":
        bv.define_user_type(type_["name"], Type.int(type_["size"], True))
    elif kind == "float":
        bv.define_user_type(type_["name"], Type.float(type_["size"]))
    elif kind == "bool":
        bv.define_user_type(type_["name"], Type.bool())
    elif kind == "pointer":
        to_type_id = type_["info"]["value_type"]
        to_type = json_object["types"][to_type_id]

        binja_type = bv.types.get(to_type["name"])
        if not binja_type:
            to_parse.append(to_type)
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["name"], Type.pointer_of_width(type_["size"], binja_type))
    elif kind == "array":
        item_type_id = type_["info"]["item_type"]
        item_type = json_object["types"][item_type_id]

        binja_type = bv.types.get(item_type["name"])
        if not binja_type:
            to_parse.append(item_type)
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["name"], Type.array(binja_type, int(type_["size"] / item_type["size"])))
    elif kind == "function":
        continue
    elif kind == "typedef":
        to_type_id = type_["info"]["alias_type"]
        to_type = json_object["types"][to_type_id]

        binja_type = bv.types.get(to_type["name"])
        if not binja_type:
            to_parse.append(to_type)
            to_parse.append(type_)
            continue

        bv.define_user_type(type_["name"], binja_type)
    else:
        print("Unknown type found. Are you using an older version of Binal?", kind)
        continue

for id_, function_ in json_object["functions"]:
    print(id_, function_)
