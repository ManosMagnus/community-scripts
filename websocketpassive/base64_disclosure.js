// * This Community Script will analyze incoming websocket messages for base64 strings

// * Regex Test: https://regex101.com/r/OOElRY/3
// ** Forked by: https://regex101.com/library/dS0sM8

// * DISCLAIMER: Function decode64 is copied by
// ** http://ntt.cc/2008/01/19/base64-encoder-decoder-with-javascript.
// ** License is included.

// Author: Manos Kirtas (manolis.kirt@gmail.com)

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

PRINT_RESULTS = new Boolean(1);

var regex_var_1 = "((?:[A-Za-z0-9+\/]{4}\n?)*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=))";

var base64Patterns = [];

base64Patterns.push(new RegExp(regex_var_1, 'g'));

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
    var counter = 0;
    var message = String(msg.getReadablePayload()).valueOf();
    base64Patterns.forEach(function(pattern){
        if(pattern.test(message)){
            var matches = message.match(pattern);
            matches.forEach(function(match){
                counter = counter + 1;
                raiseAlert(helper, msg, match, counter);
            });
        }
    });
}


function raiseAlert(helper, msgDTO, evidence, counter){
    // Test the request or response here
    if(PRINT_RESULTS){
        print("Message: " + msgDTO.getReadablePayload());
        print("Evidence: " + evidence);
        print("Decoded Evidence: " + decode64(evidence));
    }

    var risk = RISK_LOW;
    var confidence = CONFIDENCE_LOW;
    var name = "Base64-encoded string found in WebSocket message (script)";
    var description = "A Base64-encoded string has been founded in the websocket incoming message. Base64-encoded data may contain sensitive information such as usernames, passwords or cookies which should be further inspected.";

    var param = "fakeparam" + counter;
    var solution = "Base64-encoding should not be used to store or send sensitive information.";
    var reference = "";
    var cweId = 0; //the CWE ID of the issue
    var wascId  = 0; //the WASC ID of the issue

    if(true){
        helper.raiseAlert(risk, confidence, name, description, param, msgDTO, solution, evidence, reference, cweId, wascId);
    }
}

/* Base64 library for ActionScript 3.0.
 *
 * Copyright (C) 2007 Ma Bingyao <andot@ujn.edu.cn>
 * Version: 1.1
 * LastModified: Oct 26, 2007
 * This library is free.  You can redistribute it and/or modify it.
 */
var keyStr = "ABCDEFGHIJKLMNOP" +
    "QRSTUVWXYZabcdef" +
    "ghijklmnopqrstuv" +
    "wxyz0123456789+/" +
    "=";

function decode64(input) {
    var output = "";
    var chr1, chr2, chr3 = "";
    var enc1, enc2, enc3, enc4 = "";
    var i = 0;

    // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
    var base64test = /[^A-Za-z0-9\+\/\=]/g;
    if (base64test.exec(input)) {
        alert("There were invalid base64 characters in the input text.\n" +
              "Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
              "Expect errors in decoding.");
    }
    input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

    do {
        enc1 = keyStr.indexOf(input.charAt(i++));
        enc2 = keyStr.indexOf(input.charAt(i++));
        enc3 = keyStr.indexOf(input.charAt(i++));
        enc4 = keyStr.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output = output + String.fromCharCode(chr1);

        if (enc3 != 64) {
            output = output + String.fromCharCode(chr2);
        }
        if (enc4 != 64) {
            output = output + String.fromCharCode(chr3);
        }

        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";

    } while (i < input.length);

    return unescape(output);
}
