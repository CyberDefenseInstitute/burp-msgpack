import msgpack
import array
import json
from collections import OrderedDict
from msgpack import Unpacker

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IRequestInfo
from burp import ITab

from javax.swing import JMenuItem
from java.util import List, ArrayList
from javax.swing import JPanel
from javax.swing import JCheckBox

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
	
    def registerExtenderCallbacks(self, callbacks):
	self._callbacks = callbacks
	self._helpers = callbacks.getHelpers()
	callbacks.setExtensionName('Burp MessagePack Extention')
	self._mpeSettingTab = MPESettingTab(self)
	callbacks.addSuiteTab( self._mpeSettingTab )
	callbacks.registerMessageEditorTabFactory(self)
	callbacks.registerHttpListener( MPEHttpListener( self ) )
	return
	
    def createNewInstance(self, controller, editable): 
	tab = MPEDecoderTab(self, controller, editable)
	return tab

class ToolCommon():
    def __init__(self, helpers):
	self._helpers = helpers
		
    def isMessagePackMessage(self, content, isRequest):
	if content is None:
	    return False
	
	if isRequest:
	    r = self._helpers.analyzeRequest(content)
	else:
	    r = self._helpers.analyzeResponse(content)
	
	headers = r.getHeaders()
	for header in headers:
	    lowerHeader = header.lower()
	    if lowerHeader.startswith( "content-type:" ):
		contentType = lowerHeader.split(": ")[1]
		if contentType.startswith( "application/x-msgpack" ) or contentType.startswith( "application/msgpack" ) :
	    	    return True
	
	return False

class MPESettingTab(ITab, JPanel):
	
    def __init__(self, extender):
	self._extender = extender
	self._helpers = extender._helpers
	self._enableModRequestCheck = JCheckBox( "Enable mod request", False )
	self._proxyCheck = JCheckBox( "Proxy", False )
	self._intruderCheck = JCheckBox( "Intruder", False )
	self._repeaterCheck = JCheckBox( "Repeater", False )
	self._scannerCheck = JCheckBox( "Scanner", False )
	self.add( self._enableModRequestCheck )
	self.add( self._proxyCheck )
	self.add( self._intruderCheck )
	self.add( self._repeaterCheck )
	self.add( self._scannerCheck )
		
    def getTabCaption(self):
	return "MPack";
	
    def getUiComponent(self):
	return self
		
    def isToolEnable( self, toolFlag ):
	if False == self._enableModRequestCheck.isSelected():
	    return False
	
	if IBurpExtenderCallbacks.TOOL_PROXY == toolFlag:
	    return self._proxyCheck.isSelected()
	
	if IBurpExtenderCallbacks.TOOL_INTRUDER == toolFlag:
	    return self._intruderCheck.isSelected()

	if IBurpExtenderCallbacks.TOOL_REPEATER == toolFlag:
	    return self._repeaterCheck.isSelected()

	if IBurpExtenderCallbacks.TOOL_SCANNER == toolFlag:
	    return self._scannerCheck.isSelected()

	return False
	

class MPEHttpListener(IHttpListener):
    def __init__(self, extender):
	self._extender = extender
	self._helpers = extender._helpers
	self._callbacks = extender._callbacks
	self._mpeSettingTab = extender._mpeSettingTab
		
    def processHttpMessage( self, toolFlag, isRequest, httpReqRes ):
	if False == isRequest:
	    return
	
	if False == self._mpeSettingTab.isToolEnable(toolFlag):
	    return
	
	rawRequest = httpReqRes.getRequest()
	req = self._helpers.analyzeRequest( httpReqRes )
	
	if False == self._callbacks.isInScope( req.getUrl() ):
	    return
	
	if False == ToolCommon( self._helpers ).isMessagePackMessage( rawRequest, isRequest ):
	    return
	
	rawBodyMsg = rawRequest[req.getBodyOffset():].tostring()
	if "{" != rawBodyMsg[0] :
	    return
	
	bodyMsgDict = json.loads(rawBodyMsg, object_pairs_hook=OrderedDict)
	newBodyMSg = msgpack.packb( bodyMsgDict )
	newHttpMsg = self._helpers.buildHttpMessage( req.getHeaders(), self._helpers.stringToBytes( newBodyMSg ))
	
	httpReqRes.setRequest( newHttpMsg )
	return

class MPEDecoderTab(IMessageEditorTab):
	
    def __init__(self, extender, controller, editable):
	self._extender = extender
	self._helpers = extender._helpers
	self._editable = editable
	
	self._textEitor = extender._callbacks.createTextEditor()
	self._textEitor.setEditable(editable)
	return
    
    def getTabCaption(self):
	return "MPack"
		
    def getUiComponent(self):
	component = self._textEitor.getComponent()		
	return component
		
    def isEnabled(self, content, isRequest):
	return ToolCommon( self._helpers ).isMessagePackMessage(content, isRequest)
	
    def setMessage(self, content, isRequest):
	if content is None:
	    self._textEitor.setText(None)
	    self._textEitor.setEditable(False)
	    return

	if isRequest:
	    r = self._helpers.analyzeRequest(content)
	else:
	    r = self._helpers.analyzeResponse(content)
	
	rawBodyMsg = content[r.getBodyOffset():].tostring()
	mpeUnpacker = Unpacker(object_pairs_hook=OrderedDict)
	mpeUnpacker.feed(rawBodyMsg)
	mpeMsgDict =  mpeUnpacker._fb_unpack()
	showMsg = ""
	try:
	    showMsg = json.dumps(mpeMsgDict)
	except:
	    showMsg = "json decode failue:\r\n\r\n" + str( mpeMsgDict )
	
	self._textEitor.setText(showMsg)
	self._textEitor.setEditable(self._editable)
	self._currentMessage = content
	return

    def getMessage(self):
	return self._currentMessage

    def isModified(self):
	return self._textEitor.isTextModified()
	
    def getSelectedData(self):
	return self._textEitor.getSelectedText()

