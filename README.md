# Burp-MessagePack

## Requirement

* msgpack-python

## Features

* Decode MessagePack encoded request/response to JSON
* Encode JSON encoded request to MessagePack

Decode/Encode condition is below.

* A message is in Burp's target scope
* Content-Type header value is "application/\*msgpack" ("\*" means wild card)
