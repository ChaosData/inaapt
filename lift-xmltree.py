#!/usr/bin/env python3

import sys
import struct

if len(sys.argv) != 2:
  sys.stderr.write("usage : {} <aapt-xmltree-file>\n".format(sys.argv[0]))
  sys.exit(1)

def nope(s):
  pass

oldprint = print
print = nope

#$ grep 'printf("' aapt/XMLNode.cpp | grep -Ev '^\s+//'
#            printf("Using default application package: %s -> %s\n", String8(namespaceUri).string(),
#                printf("%s <!-- %s -->\n", prefix.string(), String8(com16).string());
#            printf("%sE: %s%s (line=%d)\n", prefix.string(), elemNs.string(),
#                printf("%sA: ", prefix.string());
#                    printf("%s%s(0x%08x)", ns.string(), name.string(), res);
#                    printf("%s%s", ns.string(), name.string());
#                    printf("=(null)");
#                    printf("=@0x%x", (int)value.data);
#                    printf("=?0x%x", (int)value.data);
#                    printf("=\"%s\"",
#                    printf("=(type 0x%x)0x%x", (int)value.dataType, (int)value.data);
#                    printf(" (Raw: \"%s\")", ResTable::normalizeForOutput(String8(val).string()).
#                printf("\n");
#                printf("***BAD DEPTH in XMLBlock: %d\n", depth);
#            printf("%sN: %s=%s\n", prefix.string(), ns.prefix.string(),
#                printf("***BAD DEPTH in XMLBlock: %d\n", depth);
#                printf("%s*** BAD END NS PREFIX: found=%s, expected=%s\n",
#                printf("%s *** BAD END NS URI: found=%s, expected=%s\n",
#            printf("%sC: \"%s\"\n", prefix.string(),
#        printf("Input XML from %s:\n", (const char*)file->getPrintableSource());
#        printf("Output XML:\n");
#        printf("Elem %s %s=\"%s\": set res id = 0x%08x\n",
#                printf("Attr %s: type=0x%x, str=%s\n",
#                printf("Elem %s %s=\"%s\": namespace(%s) %s ===> %s\n",
#                    printf("XML attribute name %s: resid=0x%08x\n",
#        printf("%s E: %s%s", prefix.string(),
#                printf(" / ");
#                printf(", ");
#                printf("%s%s(0x%08x)", attrNs.string(),
#                printf("%s%s", attrNs.string(), String8(attr.name).string());
#            printf("=%s", String8(attr.string).string());
#        printf("\n");
#        printf("%s N: %s=%s\n", prefix.string(),
#        printf("%s C: \"%s\"\n", prefix.string(), String8(getCData()).string());
#        printf("Start Namespace: %s %s\n", prefix, uri);
#        printf("Start Element: %s\n", name);
#        printf("CDATA: \"%s\"\n", String8(s, len).string());
#        printf("End Element: %s\n", name);
#        printf("End Namespace: %s\n", prefix);
#        printf("Comment: %s\n", comment);
#                    printf("Adding attr %s (resid 0x%08x) to pool: idx=%zd\n",
#                printf("String %s offset=0x%08zd\n", String8(attr.name).string(), idx);

text = None
with open(sys.argv[1], 'rb') as fd:
  text = fd.read().decode('utf-8')

lines = text.split('\n')

def get_indent(line):
  cnt = 0
  for c in line:
    if c == ' ':
      cnt += 1
    else:
      break
  if cnt % 2 == 1:
    sys.stderr.write("invalid odd-space count indented line: " + repr(line))
    sys.exit(1)
  return cnt // 2

def get_node(nodes, path):
  cn = nodes
  for p in path:
    try:
      cn = cn['children'][p]
    except Exception as e:
      print("===")
      print("nodes: " + str(nodes))
      print("path: " + str(path))
      print("cn: " + str(cn))
      print(p)
      raise e
  return cn

def new_node(nodes, path, desc):
  np = path[:]
  if not desc:
    np.pop()
  cn = get_node(nodes, np)

  try:
    c = len(cn['children'])
  except Exception as e:
    print("===")
    print("path: " + str(path))
    print("cn: " + str(cn))
    raise e

  cn['children'].append( { 'children': [] } )
  np.append(c)
  return np

def get_node_type(line):
  l = line.lstrip()
  if len(l) < 2:
    return None
  t = l[0]
  if t == 'N':
    return "namespace"
  elif t == 'E':
    return "element"
  elif t == 'A':
    return "attribute"
  return None

def get_segment(line, prefix):
  pos = line.find(prefix)
  if pos == -1:
    return None
  pos += len(prefix)
  return line[pos:].rstrip()

def get_namespace(line, lineno):
  nsseg = get_segment(line, "N: ")
  if nsseg is None:
    sys.stderr.write("Error: Could not find start of Namespace on line {} ...skipping\n".format(lineno))
    return {}
  eqpos = nsseg.find('=')
  if eqpos == -1:
    sys.stderr.write("Error: Could not find = in namespace=schema_uri format of Namespace on line {} ...skipping\n".format(lineno))
    return {}
  name = nsseg[:eqpos]
  uri = nsseg[eqpos+len('='):]
  return { "namespace": name, "schema_uri": uri }

def get_element(line):
  elseg = get_segment(line, "E: ")
  if elseg is None:
    sys.stderr.write("Error: Could not find start of Element on line {} ...skipping\n".format(lineno))
    return {}
  spos = elseg.find(' ')
  line = None
  if spos == -1:
    name = elseg
  else:
    name = elseg[:spos]
    parensline = elseg[spos+len(' '):]
    if len(parensline) < 3:
      sys.stderr.write("Error: Invalid format or number of characters in Element on line {} ...skipping\n".format(lineno))
      return {}
    else:
      line = parensline[1:-1]
      lineeqpos = line.find("line=")
      if lineeqpos == -1:
        sys.stderr.write("Error: Could not find = in (line=####) format of Element on line {} ...skipping\n".format(lineno))
        return {}
      else:
        line = line[lineeqpos+len("line="):]
        try:
          line = int(line)
        except ValueError:
          sys.stderr.write("Error: Invalid format of line number in Element on line {} ...skipping\n".format(lineno))
          return {}
  return { "element": name, "line": line }

RESOURCE_TYPES = {
# types:
#   id 0x00: null
#     value:
#       0: undefined
#       1: empty
  "null": 0x00,
#   id 0x01: reference
#     value:
#       reference to a resource table entry
  "reference": 0x01,
#   id 0x02: attribute
#     value:
#       attribute resource identifier
  "attribute": 0x02,
#   id 0x03: string
#     value:
#       index into global value string pool of containing resource table
  "string": 0x3,
#   id 0x04: float
#     value:
#       single-precision float
  "float": 0x04,
#   id 0x05: dimension
#     value:
#       complex number encoding a dimension
  "dimension": 0x05,
#   id 0x06: fraction
#     value:
#       complex number encoding fraction of a container
  "fraction": 0x06,
#   id 0x07: dynamic-reference
#     value:
#       dynamic reference to a resource table that must be resolved prior to
#       using it as type 0x01 reference
  "dynamic-reference": 0x07,
#   id 0x08: dynamic-attribute
#     value:
#       dynamic reference to an attribute resource identifier that must be
#       resolved prior to using it as a type 0x02 attribute
  "dynamic-attribute": 0x08,
#   id 0x09-0x0f: RESERVED
#   id 0x10: int-dec
#     value:
#       an integer that was originally specified in decimal (base 10)
  "int-dec": 0x10,
#   id 0x11: int-hex
#     value:
#       an integer that was originally specified in hexadecimal (base 16)
  "int-hex": 0x11,
#   id 0x12: boolean
#     value:
#       0: false (represented by aapt as 0x0)
#       1: true (represented by aapt as 0xffffffff)
  "boolean": 0x12,
#   id 0x13-0x1b: RESERVED
#   id 0x1c: argb8
#     value:
#       an integer that was originally specified in the form: #aarrggbb
  "argb8": 0x1c,
#   id 0x1d: rgb8
#     value:
#       an integer that was originally specified in the form: #rrggbb
  "rgb8": 0x1d,
#   id 0x1e: argb4
#     value:
#       an integer that was originally specified in the form: #argb
  "argb4": 0x1e,
#   id 0x1f: rgb4
#     value:
#       an integer that was originally specified in the form: #rgb
  "rgb4": 0x1f,
}
RESOURCE_TYPES_BY_ID = {v:k for k,v in RESOURCE_TYPES.items()}


# expects end-quotes stripped
def is_valid_string(s):
  i = 0
  while i < len(s):
    if s[i] == '\x5c':
      if i < len(s)-1:
        return False
      if s[i+1] not in ['\x5c', 'n', '"']:
        return False
      i += 1
    elif s[i] == '"':
      if i < 0:
        return False
      if s[i-1] != '\x5c':
        return False
    i += 1
  return True

def get_attribute(line, lineno):
  atseg = get_segment(line, "A: ")
  if atseg is None:
    return {}
  oppos = atseg.find('(')
  if oppos == -1:
    sys.stderr.write("Error: Missing '(' for line= in Attribute on line {} ...skipping\n".format(lineno))
    return {}
  key = atseg[:oppos]
  rem = atseg[oppos+len('('):]
  cppos = rem.find(')')
  if cppos == -1:
    sys.stderr.write("Error: Missing ')' for line= in Attribute on line {} ...skipping\n".format(lineno))
    return {}
  key_id = rem[:cppos]
  rem = rem[cppos+len(')'):]
  if len(rem) < 2 or rem[0] != '=':
    sys.stderr.write("Error: [1] Not enough characters in Attribute on line {} ...skipping\n".format(lineno))
    return {}
  rem = rem[1:]

  # so... based on the code, any value can have a string representation that
  # gets the (Raw: "...") treatment. I've only really ever seen this for
  # strings though, but we will attempt to handle it here for correctness. :|

  fc = rem[0]
  if len(rem) > 2:
    if rem.endswith('")'):
      raw = rem[:-2]
      rawpos = raw.rfind(' (Raw: "') # only ok b/c we validate it after
      raw = raw[rawpos+len(' (Raw: "'):]
      if not is_valid_string(raw):
        sys.stderr.write("Error: (Raw: \"...\") string is not a valid string in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      rem = rem[:rawpos]
    else:
      raw = None
  else:
    sys.stderr.write("Error: Not enough characters in value of in Attribute on line {} ...skipping\n".format(lineno))
    return {}

  if fc == '"':   # string
    if len(rem) < 2 or rem[-1] != '"':
      sys.stderr.write("Error: [2] Not enough characters in Attribute on line {} ...skipping\n".format(lineno))
      return {}
    rem = rem[1:-1]
    if not is_valid_string(rem):
      sys.stderr.write("Error: value is not a valid string in Attribute on line {} ...skipping\n".format(lineno))
      return {}

    # per https://android.googlesource.com/platform/frameworks/base/+/pie-release/libs/androidfw/ResourceTypes.cpp#7270
    # we decode just the encoded sequences
    value_lit = '"' + rem + '"'
    value = rem.replace('\x5c\x5c', '\x5c').replace('\x5cn', '\n').replace('\x5c"', '"')
    value_type = "string"
    value_type_id = RESOURCE_TYPES[value_type]
  elif fc == '@': # reference
    if len(rem) < len("@0xF") or len(rem) > len("@0xFFFFFFFF") or not rem.startswith("@0x"):
      sys.stderr.write("Error: Invalid format or number of characters in Attribute on line {} ...skipping\n".format(lineno))
      return {}
    try:
      value_lit = rem[1:]
      value = int(value_lit, 16)
      value_type = "reference"
      value_type_id = RESOURCE_TYPES[value_type]
    except ValueError:
      sys.stderr.write("Error: Invalid format of reference value in Attribute on line {} ...skipping\n".format(lineno))
      return {}
  elif fc == '?': # attribute
    if len(rem) < len("?0xF") or len(rem) > len("?0xFFFFFFFF") or not rem.startswith("?0x"):
      sys.stderr.write("Error: Invalid format or number of characters in Attribute on line {} ...skipping\n".format(lineno))
      return {}
    try:
      value_lit = rem[1:]
      value = int(value_lit, 16)
      value_type = "attribute"
      value_type_id = RESOURCE_TYPES[value_type]
    except ValueError:
      sys.stderr.write("Error: Invalid format of attribute value in Attribute on line {} ...skipping\n".format(lineno))
      return {}
  elif fc == '(': # (type)value or (null)
    if rem == "(null)":
      value_lit = "(null)"
      value = None # aapt doesn't actually print the 0/1 value for null type :|
      value_type = "null"
      value_type_id = RESOURCE_TYPES[value_type]
    else:
      # (type 0x%x)0x%x
      # the first %x is of a uint8_t
      if len(rem) < (len("(type 0xF")+len(")0xF")) or len(rem) > (len("(type 0xFF")+len(")0xFFFFFFFF")) or not rem.startswith("(type 0x"):
        sys.stderr.write("Error: Invalid format or number of characters in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      h1pos = rem.find('0x')
      cppos = rem.find(')0x')
      if cppos == -1:
        sys.stderr.write("Error: Invalid (type 0x??)0x???????? format in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      value_type_id_lit = rem[h1pos:cppos]
      if len(value_type_id_lit) not in [len("0xF"), len("0xFF")]:
        sys.stderr.write("Error: Invalid value type id length in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      try:
        value_type_id = int(value_type_id_lit, 16)
      except ValueError:
        sys.stderr.write("Error: Invalid format of attribute value in Attribute on line {} ...skipping\n".format(lineno))
        return {}

      if value_type_id not in RESOURCE_TYPES_BY_ID:
        sys.stderr.write("Warn: Unrecognized type ID for attribute value in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      value_type = RESOURCE_TYPES_BY_ID[value_type_id]

      rem = rem[cppos+len(')'):]

      value_lit = rem[:]
      if len(value_lit) not in list(range(len("_0xFFFFFFFF"))[3:]):
        sys.stderr.write("Error: Invalid value length in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      try:
        value = int(value_lit, 16)
      except ValueError:
        sys.stderr.write("Error: Invalid format of attribute value in Attribute on line {} ...skipping\n".format(lineno))
        return {}

      if value_type_id in [
        RESOURCE_TYPES["null"], RESOURCE_TYPES["reference"],
        RESOURCE_TYPES["attribute"], RESOURCE_TYPES["string"]
      ]:
        sys.stderr.write("Error: null/reference/attribute/string in generic format in Attribute on line {} ...skipping\n".format(lineno))
        return {}
      if value_type_id == RESOURCE_TYPES["float"]:
        value = struct.unpack(">f", struct.pack(">I", value))
      elif value_type_id == RESOURCE_TYPES["dimension"]:
        pass
      elif value_type_id == RESOURCE_TYPES["fraction"]:
        pass
      elif value_type_id == RESOURCE_TYPES["dynamic-reference"]:
        pass
      elif value_type_id == RESOURCE_TYPES["dynamic-attribute"]:
        pass
      elif value_type_id == RESOURCE_TYPES["int-dec"]:
        pass
      elif value_type_id == RESOURCE_TYPES["int-hex"]:
        pass
      elif value_type_id == RESOURCE_TYPES["boolean"]:
        pass
      elif value_type_id == RESOURCE_TYPES["argb8"]:
        pass
      elif value_type_id == RESOURCE_TYPES["rgb8"]:
        pass
      elif value_type_id == RESOURCE_TYPES["argb4"]:
        pass
      elif value_type_id == RESOURCE_TYPES["rgb4"]:
        pass
      else:
        sys.stderr.write("Warn: Unrecognized type ID for attribute value in Attribute on line {} ...skipping\n".format(lineno))
        return {}
  else:
    sys.stderr.write("Warn: Unrecognized format of Attribute on line {} ...skipping\n".format(lineno))
    return {}
  return {
    "value": value,
    "type": value_type,
    "type_id": value_type_id,
    "value_literal": value_lit,
    "value_raw": raw
  }

nodes = { 'children': [] }
idt_stack = []
cur_node_path = []
cur_node = None
for i in range(len(lines)):
  line = lines[i]
  print(repr(line))
  print("idt_stack (before): " + str(idt_stack))
  print("cur_node_path (before): " + str(cur_node_path))
  print(nodes)
  desc = False
  asc = False
  cur_idt = get_indent(line)
  if len(idt_stack) == 0:
    idt_stack.append(cur_idt)
    desc = True
    cur_node_path = new_node(nodes, cur_node_path, desc)
    cur_node = get_node(nodes, cur_node_path)
  elif cur_idt == idt_stack[-1]:
    cur_node_path = new_node(nodes, cur_node_path, desc)
    cur_node = get_node(nodes, cur_node_path)
  elif cur_idt > idt_stack[-1]:
    desc = True
    cur_node_path = new_node(nodes, cur_node_path, desc)
    cur_node = get_node(nodes, cur_node_path)
    idt_stack.append(cur_idt)
  elif cur_idt < idt_stack[-1]:
    asc = True
    while True:
      last = idt_stack.pop()
      if cur_idt < last:
        cur_node_path.pop()
        continue
      elif cur_idt == last:
        idt_stack.append(last)
      break
    cur_node_path = new_node(nodes, cur_node_path, desc)
    cur_node = get_node(nodes, cur_node_path)

  print("idt_stack (after): " + str(idt_stack))
  print("cur_node_path (after): " + str(cur_node_path))

  cur_node['line'] = line

  nt = get_node_type(line)
  cur_node['node_type'] = nt

  if nt == "namespace":
    cur_node.update(get_namespace(line, i+1))
  elif nt == "element":
    cur_node.update(get_element(line))
  elif nt == "attribute":
    cur_node.update(get_attribute(line, i+1))

  cur_node['children'] = cur_node.pop('children')
  print("============")

import json
print = oldprint
print(json.dumps(nodes))
