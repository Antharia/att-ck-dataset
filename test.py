import mad

def prettify(output):
    return output.serialize(pretty=True)

def get_aliases(src, alias):
    """
    Get all aliases of one group by name
    """
    aliases = mad.get_group_by_alias(src, alias).aliases
    print(f"Aliases of {alias} :")
    for a in aliases:
        print(f" - {a}")
    return mad.get_group_by_alias(src, alias).aliases

src = mad.FileSystemSource("./cti/enterprise-attack")

get_aliases(src, "APT29")

output = mad.get_group_by_alias(src, "Cozy Bear")
print(prettify(output))


