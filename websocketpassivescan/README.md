WebSocket Passive Scan scripts
=============================

Scripts that can perform passive scanning on WebSocket  messages and raise alerts. 

## Javascript Template 
```JavaScript
// Passive scan rules should not send messages
// Right click the script in the Scripts tree and select "enable"  or "disable"

OPCODE_CONTINUATION = 0x0;

OPCODE_TEXT = 0x1;
OPCODE_BINARY = 0x2;

OPCODE_CLOSE = 0x8;
OPCODE_PING = 0x9;
OPCODE_PONG = 0xA;

RISK_INFO 	= 0;
RISK_LOW 	= 1;
RISK_MEDIUM = 2;
RISK_HIGH 	= 3;

CONFIDENCE_LOW = 1;
CONFIDENCE_MEDIUM = 2;
CONFIDENCE_HIGH = 3;

/**
 * This function scans passively WebSocket messages. The scan function will be called for
 * messages via ZAP.
 *
 * @param helper - the WebSocketPassiveScanAlert interface provides the raiseAlert method in order
 *               to raise the appropriate alerts
 * @param msg - the Websocket Message being scanned. This is a WebSocketMessage object.
 *
 * Some useful functions and fields of WebSocketMessageDTO:
 * msg.channel        -> Channel of the message (WebSocketChannelDTO)
 * msg.id             -> Unique ID of the message (int)
 * msg.opcode         -> Opcode of the message (int) (Opcodes defined bellow)
 * msg.readableOpcode -> Textual representation of opcode (String)
 * msg.isOutgoing     -> Outgoing or incoming message (boolean)
 * msg.getReadablePayload() -> Return readable representation of payload
 *
 * Some useful functions and fields of WebSocketChannelDTO:
 * channel.id         -> Unique ID of the message (int)
 * channel.host       -> Host of the WebSocket Server (String)
 * channel.port       -> Port where the channel is connected at. Usually at 80 or 443.
 * channel.url        -> URL used in HTTP handshake.
 */
function scan(helper,msg) {

    if(msg.opcode != OPCODE_TEXT || msg.isOutgoing){
        return;
    }

    // Test the request or response here
    print(msg.getReadablePayload());

    var risk = 0;
    var confidence = 0;
    var name = "name of the alert";
    var description = "the description of the alert";
    var param = "the parameter that has the issue";

    var solution = "the solution for the issue";
    var evidence = "the evidence (in the WebSocket message) that the issue exists";
    var reference = "references about the issue";
    var cweId = 0; //the CWE ID of the issue
    var wascId  = 0; //the WASC ID of the issue

    if(true){
        helper.raiseAlert(risk, confidence, name, description, param, msg, solution, evidence, reference, cweId, wascId);
    }
}

```

## Python Template

```Python
"""
Passive scan rules should not send messages
Right click the script in the Scripts tree and select "enable"  or "disable"
"""

OPCODE_CONTINUATION = 0x0

OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2

OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

RISK_INFO 	= 0
RISK_LOW 	= 1
RISK_MEDIUM = 2
RISK_HIGH 	= 3

CONFIDENCE_LOW = 1
CONFIDENCE_MEDIUM = 2
CONFIDENCE_HIGH = 3

"""
 * This function scans passively WebSocket messages. The scan function will be called for
 * messages via ZAP. 
 *
 * @param helper - the WebSocketPassiveScanAlert interface provides the raiseAlert method in order
 *               to raise the appropriate alerts
 * @param msg - the Websocket Message being scanned. This is an WebSocketMessage object.
 *
 * Some useful functions and fields of WebSocketMessageDTO:
 * msg.channel        -> Channel of the message (WebSocketChannelDTO)
 * msg.id             -> Unique ID of the message (int)
 * msg.opcode         -> Opcode of the message (int) (Opcodes defined bellow)
 * msg.readableOpcode -> Textual representation of opcode (String)
 * msg.isOutgoing     -> Outgoing or incoming message (boolean)
 * msg.getReadablePayload() -> Return readable representation of payload
 *
 * Some useful functions and fields of WebSocketChannelDTO:
 * channel.id         -> Unique ID of the message (int)
 * channel.host       -> Host of the WebSocket Server (String)
 * channel.port       -> Port where this channel is connected at. Usually 80 or 443.
 * channel.url        -> URL used in HTTP handshake.
"""
def scan(helper,msg):

    if( msg.opcode != OPCODE_TEXT or msg.isOutgoing):
        return

    print(msg.getReadablePayload())

    risk = 0
    confidence = 0
    name = "name of the alert"
    description = "the description of the alert"
    param = "the parameter that has the issue"
    solution = "solution for the issue"
    evidence = "evidence (in the WebSocket message) that the issue exists"
    reference = "references about the issue"
    cweId = 0  #the CWE ID of the issue
    wascId  = 0 #the WASC ID of the issue

    if(True):
        helper.raiseAlert(risk, confidence, name, description, param, msg, solution, evidence, reference, cweId, wascId)
```

## Parameters 

| Name   | Source                                                                                                                                                                   |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| helper | WebSocketPassiveScanAlert                                                                                                                                                |
| msg    | [WebSocketMessageDTO](https://github.com/zaproxy/zap-extensions/blob/master/addOns/websocket/src/main/java/org/zaproxy/zap/extension/websocket/WebSocketMessageDTO.java) |
