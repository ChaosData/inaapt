#!/usr/bin/env python3

import sys
import json

if len(sys.argv) != 1:
  sys.stderr.write("usage: ./lift-xmltree.py <aapt-xmltree-file> | {}\n".format(sys.argv[0]))
  sys.exit(1)

text = sys.stdin.read()
#print(text)
nodes = json.loads(text)
root = nodes['children'][0]


namespace = None
schema_uri = None

def recurse(node, depth=0):
  global namespace
  global schema_uri
  if node['node_type'] == 'namespace':
    sys.stdout.write('<?xml version="1.0" encoding="utf-8"?>\n')
    namespace = node['namespace']
    schema_uri = node['schema_uri']
    for child in node['children']:
      recurse(child, depth)
  elif node['node_type'] == 'element':
    sys.stdout.write('{}<{}'.format('    '*depth, node['element']))
    if node['element'] == 'manifest':
      sys.stdout.write(' {}="{}"'.format(namespace, schema_uri))
    attribute_nodes = [child for child in node['children'] if child['node_type'] == 'attribute']
    element_nodes = [child for child in node['children'] if child['node_type'] == 'element']
    if len(attribute_nodes) == 1:
      sys.stdout.write(' {}={}'.format(attribute_nodes[0]['key'], attribute_nodes[0]['value_literal']))
    else:
      for attribute in attribute_nodes:
        recurse(attribute, depth+1)
    if len(element_nodes) == 0:
      sys.stdout.write(' />\n')
    else:
      sys.stdout.write(' >\n')
      for element in element_nodes:
        recurse(element, depth+1)
      sys.stdout.write('{}</{}>\n'.format('    '*depth, node['element']))
  elif node['node_type'] == 'attribute':
    sys.stdout.write('\n{}{}={}'.format('    '*depth, node['key'], node['value_literal']))

recurse(root)
