# BurpMessagePackExtention.py

## Requirement

* msgpack-python

## Features

### Decode MessagePack encoded message

BurpMessagePackExtention decodes MessagePack encoded message to JSON.
See each http message's "MPack" tab.

### Send MessagePack request

1. Add Target Scope from Target tab.
1. Open MPack tab and check "Enable mod request".
1. Check burptools you want to use encoding feature.
1. Move to any http request tab which you want to modify.
1. Copy "MPack" tab's message(JSON) to Raw tab's body.
1. Send http request. Extention will encode automatically.

Encode condition is below.

* A message is in target scope.
* "Enable mod request" checkbox has checked.
* burptool's checkboxes has checked.
* Content-Type
 * application/msgpack
 * application/x-msgpack
* A message body is JSON formatted.