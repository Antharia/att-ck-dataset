import mad
import stix2

src = mad.FileSystemSource("./cti/enterprise-attack")

output = mad.get_group_by_alias(src, "Cozy Bear")
output = output.serialize(pretty=True)
print(str(output))
