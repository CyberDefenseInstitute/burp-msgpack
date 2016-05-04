import msgpack
import array
import json
import re
from collections import OrderedDict
from msgpack import Unpacker

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
from burp import IProxyListener

class BurpExtender( IBurpExtender ):
	
    def registerExtenderCallbacks( self, callbacks ):
	self._callbacks = callbacks
	self._helpers = callbacks.getHelpers()
	callbacks.setExtensionName( "Burp MessagePack" )
        callbacks.registerProxyListener( ProxyListener( self ) )
	callbacks.registerHttpListener( HttpListener( self ) )

class ListenerBase:
    def __init__( self, extender ):
	self._helpers = extender._helpers
	self._callbacks = extender._callbacks
        self._mpackPattern = re.compile( "^content-type: .*?application/[^;]*?msgpack", re.IGNORECASE )
        self._jsonPattern = re.compile( "[{\[]" )

    def isMessagePack( self, headers ):
	for header in headers:
	    if None != self._mpackPattern.match( header ):
                return True
	return False

    def buildHttpMessage( self, info, newBody ):
        newRaw = self._helpers.buildHttpMessage( info.getHeaders(), self._helpers.stringToBytes( newBody ))
        return newRaw

    def toJsonBody( self, mpackBody ):
        unpacker = Unpacker( object_pairs_hook=OrderedDict )
        unpacker.feed( mpackBody )
        bodyMap =  unpacker._fb_unpack()
        newBody = json.dumps( bodyMap, ensure_ascii=False )
        return newBody

    def toJson( self, raw, info ):
        mpackBody = raw[ info.getBodyOffset() : ].tostring()
        newBody = self.toJsonBody( mpackBody )
        newRaw = self.buildHttpMessage( info, newBody )
        return newRaw

    def toMpackBody( self, body ):
        jsonBody = json.loads( body, object_pairs_hook=OrderedDict )
        newBody = msgpack.packb( jsonBody )
        return newBody

    def toMpack( self, raw, info ):
        body = raw[ info.getBodyOffset() : ].tostring()
        if None == self._jsonPattern.match( body[0] ):
            return
        newBody = self.toMpackBody( body )
        newRaw = self.buildHttpMessage( info, newBody )
        return newRaw

class ProxyListener(IProxyListener, ListenerBase):
    def __init__(self, extender):
	ListenerBase.__init__( self, extender )

    def processProxyMessage( self, isRequest, proxyMessage ):
        httpReqRes = proxyMessage.getMessageInfo()
        requestInfo = self._helpers.analyzeRequest( httpReqRes )
        if False == self._callbacks.isInScope( requestInfo.getUrl() ):
            return
 	
        if isRequest:
            if False == self.isMessagePack( requestInfo.getHeaders() ):
                return
            rawRequest = httpReqRes.getRequest()
            mpackBody = rawRequest[ requestInfo.getBodyOffset() : ].tostring()
            newBody = self.toJsonBody( mpackBody )
            
            # re-encode test
            try:
                self.toMpackBody( newBody )
            except:
                # If this test is failed, following HttpListener.processHttpMessage always fail.
                # So, we can't modify http message.
                self._callbacks.printError( "A messagepack'ed request re-encode failure: " + newBody )
                return
            newRequest = self.buildHttpMessage( requestInfo, newBody )
            httpReqRes.setRequest( newRequest )
        else:
            rawResponse = httpReqRes.getResponse() 
            responseInfo = self._helpers.analyzeResponse( rawResponse )
            if False == self.isMessagePack( responseInfo.getHeaders() ):
                return
            newResponse = self.toMpack( rawResponse, responseInfo )
            httpReqRes.setResponse( newResponse )

class HttpListener( IHttpListener, ListenerBase ):
    def __init__( self, extender ):
	ListenerBase.__init__( self, extender )

    def processHttpMessage( self, toolFlag, isRequest, httpReqRes ):
        requestInfo = self._helpers.analyzeRequest( httpReqRes )
        if False == self._callbacks.isInScope( requestInfo.getUrl() ):
            return
        
        if isRequest:
            if False == self.isMessagePack( requestInfo.getHeaders() ):
                return
            rawRequest = httpReqRes.getRequest()
            newRequest = self.toMpack( rawRequest, requestInfo )
            if None == newRequest:
                return
            httpReqRes.setRequest( newRequest )
        else:
	    rawResponse = httpReqRes.getResponse() 
            responseInfo = self._helpers.analyzeResponse( rawResponse )
            if False == self.isMessagePack( responseInfo.getHeaders() ):
                return
            
            mpackBody = rawResponse[ responseInfo.getBodyOffset() : ].tostring()
            newBody = self.toJsonBody( mpackBody )

            if IBurpExtenderCallbacks.TOOL_PROXY == toolFlag:
                # re-encode test
                try:
                    self.toMpackBody( newBody )
                except:
                    self._callbacks.printError( "A messagepack'ed response re-encode failure: " + newBody )
                    return
                
            newResponse = self.buildHttpMessage( responseInfo, newBody )
            httpReqRes.setResponse( newResponse )

