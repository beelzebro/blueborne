import struct

def _reverse_dict(d):
    return dict(list(map(reversed, list(d.items()))))

def create_struct_funcs(format_, definition):
    struct_format = format_ + ''.join([field[1] for field in definition])
    keys = list([field[0] for field in definition])
    mappers = dict([(field[0], field[2]) for field in [field for field in definition if len(field) > 2]])
    reverse_mappers = dict([(item[0], _reverse_dict(item[1])) for item in list(mappers.items())])

    def pack(**kwargs):
        unknown_fields = set(kwargs.keys()) - set(keys)
        missing_fields = set(keys) - set(kwargs.keys())
        if len(unknown_fields) > 0:
            raise TypeError('Unknown field(s): {!r}'.format(unknown_fields))
        if len(missing_fields) > 0:
            raise TypeError('Missing field(s): {!r}'.format(missing_fields))
        for key, mapper in list(mappers.items()):
            kwargs[key] = mapper[kwargs[key]]
        return struct.pack(struct_format, *[kwargs[key] for key in keys])

    def unpack(data):
        result = dict(list(zip(keys, struct.unpack(struct_format, data))))
        for key, mapper in list(reverse_mappers.items()):
            result[key] = mapper[result[key]]
        return result

    def size():
        return struct.calcsize(struct_format)

    return pack, unpack, size

