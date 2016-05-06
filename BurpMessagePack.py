import msgpack
import json
import re
from collections import OrderedDict
from msgpack import Unpacker

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IHttpListener

class BurpExtender( IBurpExtender, IMessageEditorTabFactory ):
	
    def registerExtenderCallbacks( self, callbacks ):
        self._callbacks = callbacks
	callbacks.setExtensionName( "Burp MessagePack" )
        callbacks.registerMessageEditorTabFactory( self )
        callbacks.registerHttpListener( HttpListener( callbacks ) )

    def createNewInstance( self, controller, editable ):
        return MessageEditorTab( controller, editable, self._callbacks )

class MpackJsonHelper:
    def __init__( self, callbacks ):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._mpackPattern = re.compile( "^content-type: .*?application/[^;]*?msgpack", re.IGNORECASE )
        self._jsonPattern = re.compile( "[{\[]" )

    def analyzeMessage( self, content, isRequest ):
        if isRequest:
            httpService = self._controller.getHttpService()
            info = self._helpers.analyzeRequest( httpService, content )
        else:
            info = self._helpers.analyzeResponse( content )
        return info

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
        bodyMap =  unpacker.unpack()
        newBody = json.dumps( bodyMap, ensure_ascii=False )
        return newBody

    def toJson( self, raw, info ):
        mpackBody = raw[ info.getBodyOffset() : ].tostring()
        newBody = self.toJsonBody( mpackBody )
        newRaw = self.buildHttpMessage( info, newBody )
        return newRaw

    def toMpackBody( self, body ):
        try:
            jsonBody = json.loads( body, object_pairs_hook=OrderedDict )
            newBody = msgpack.packb( jsonBody )
        except:
            msg = "toMpackBody failure: " + str(body)
            self._callbacks.issueAlert( msg )
            raise Exception( msg )
        return newBody

    def toMpack( self, raw, info ):
        body = raw[ info.getBodyOffset() : ].tostring()
        if None == self._jsonPattern.match( body[0] ):
            return
        newBody = self.toMpackBody( body )
        newRaw = self.buildHttpMessage( info, newBody )
        return newRaw

class MessageEditorTab( IMessageEditorTab, MpackJsonHelper ):
    def __init__( self, controller, editable, callbacks ):
        MpackJsonHelper.__init__( self, callbacks )
        self._controller = controller
        self._editable = editable
        self._editor = self._callbacks.createTextEditor()
        self._editor.setEditable( editable )

    def getTabCaption( self ):
        return "mpack"

    def getUiComponent( self ):
        return self._editor.getComponent()

    def isEnabled( self, content, isRequest ):
        if content is None:
            return False

        info = self.analyzeMessage( content, isRequest )
        isMessagePack = self.isMessagePack( info.getHeaders() )
        return isMessagePack

    def setMessage( self, content, isRequest ):
        info = self.analyzeMessage( content, isRequest )
        newRaw = self.toJson( content, info )
        self._editor.setText( newRaw )
        self._content = content
        self._isRequest = isRequest

    def getMessage( self ):
        content = self._editor.getText()
        info = self.analyzeMessage( content, self._isRequest )
        try:
            newContent = self.toMpack( content, info )
        except:
            return self._content
        return newContent

    def isModified( self ):
        return self._editor.isTextModified()

    def getSelectedData( self ):
        selected = self._editor.getSelectedText()
        return selected

class HttpListener( IHttpListener, MpackJsonHelper ):
    def __init__( self, callbacks ):
        MpackJsonHelper.__init__( self, callbacks )
        self._toolMask = self._callbacks.TOOL_SCANNER | \
            self._callbacks.TOOL_INTRUDER | \
            self._callbacks.TOOL_EXTENDER

    def processHttpMessage( self, toolFlag, isRequest, httpReqRes ):
        if False == isRequest:
            return
        if 0 == ( self._toolMask & toolFlag ):
            return
        requestInfo = self._helpers.analyzeRequest( httpReqRes )
        if False == self._callbacks.isInScope( requestInfo.getUrl() ):
            return
        if False == self.isMessagePack( requestInfo.getHeaders() ):
            return

        rawRequest = httpReqRes.getRequest()
        try:
            newRequest = self.toMpack( rawRequest, requestInfo )
            if None == newRequest:
                return
        except:
            return
        httpReqRes.setRequest( newRequest )
