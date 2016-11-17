/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request'),
  watson = require('watson-developer-cloud'),
  RapidAPI = new require('rapidapi-connect'),
  rapid = new RapidAPI('jimbot', 'INSERT'),
  db_username = 'INSERT';

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

// Database authentication key.
const DB_AUTH = (process.env.DB_AUTH) ?
  (process.env.DB_AUTH) :
  config.get('dbAuth');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/', function(req, res) {
    console.log("default");
    res.status(200).sendFile('public/index.html');
});

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "INSERT";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

function splitWithTail(str, delim, count) {
  var parts = str.split(delim);
  var tail = parts.slice(count).join(delim);
  var result = parts.slice(0,count);
  result.push(tail);
  return result;
}

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    try {
      var payload = JSON.parse(quickReplyPayload);
    } catch (e) {
      console.log("Bad JSON in quick reply payload", quickReplyPayload);
      return;
    }
    switch (payload['type']) {
      case 'meet':
        console.log("Contacting members");
        contactMembers(senderID, payload);
        break;

      default:
        sendTextMessage(senderID, "Quick reply tapped");
        break;
    }
    return;
  }

  if (messageText) {
    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    console.log('===' + messageText + '===');
      if (messageText.match(/^@image/g)) {
        sendImageMessage(senderID);
      } else if (messageText.match(/^@gif/g)) {
        sendGifMessage(senderID);
      } else if (messageText.match(/^@audio/g)) {
        sendAudioMessage(senderID);
      } else if (messageText.match(/^@video/g)) {
        sendVideoMessage(senderID);
      } else if (messageText.match(/^@file/g)) {
        sendFileMessage(senderID);
      } else if (messageText.match(/^@button/g)) {
        sendButtonMessage(senderID);
      } else if (messageText.match(/^@generic/g)) {
        sendGenericMessage(senderID);
      } else if (messageText.match(/^@receipt/g)) {
        sendReceiptMessage(senderID);
      } else if (messageText.match(/^@quick reply/g)) {
        sendQuickReply(senderID);
      } else if (messageText.match(/^@read receipt/g)) {
        sendReadReceipt(senderID);
      } else if (messageText.match(/^@typing on/g)) {
        sendTypingOn(senderID);
      } else if (messageText.match(/^@typing off/g)) {
        sendTypingOff(senderID);
      } else if (messageText.match(/^@account linking/g)) {
        sendAccountLinking(senderID);
      } else if (messageText.match(/^@cat/g)) {
        sendCatPicture(senderID);
      } else if (messageText.match(/^@location .+/g)) {
        sendLocation(senderID, messageText.replace(/^@location /, ''));
      } else if (messageText.match(/^@send \S+ .+/g)) {
        var args = splitWithTail(messageText, ' ', 2);
        console.log("Message send to custom user!");
        console.log(args);
        sendTextMessage(args[1], args[2]);
      } else if (messageText.match(/^@group \S+ \S+/g)) {
        var args = splitWithTail(messageText,' ', 2);
        handleGroup(senderID, args[1], args[2])
      } else if (messageText.match(/^@location/g)) {
        getLocation(senderID);
      } else if(messageText.match(/^@trip .+/g)) {
        var args = splitWithTail(messageText, ' ', 1);
        startTrip(senderID, args[1]);
      } else if (messageText.match(/^@meet \S+ \S+ \d+/g)) {
        var args = splitWithTail(messageText, ' ', 3);
        planMeet(senderID, args[1], args[2], parseInt(args[3], 10));
      } else {
        sendTextMessage(senderID, messageText);
      }
  } else if (messageAttachments) {
    // console.log('message', message);
    var type = messageAttachments[0].type;
    console.log('type', type);
    if (type == 'location') {
      var coordinates = messageAttachments[0].payload.coordinates;
      saveLocation(senderID, coordinates.lat, coordinates.long);
      console.log("Location for %s updated", senderID);
    } else if (type == 'image') {
      var image_url = messageAttachments[0].payload.url;
      recognizeLocation(senderID, image_url);
    } else {
      console.log('Other attachment type', type);
      sendTextMessage(senderID, "Message with attachment received");
    }
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a file using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "INSERT"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",               
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",               
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;


/*
 * Send a Gif using the Send API.
 *
 */
function sendCatPicture(recipientId) {
  rapid.call('Giphy', 'translateTextToGif', { 
  'rating': '',
  'lang': '',
  'apiKey': 'INSERT',
  'text': 'cat'
 
  }).on('success', (payload)=>{
    console.log('Successfully get cat picture');
    var messageData = {
      recipient: {
        id: recipientId
      },
      message: {
        attachment: {
          type: "image",
          payload: {
            url: payload.data.images.original.url
          }
        }
      }
    };

  callSendAPI(messageData);
  }).on('error', (payload)=>{
     console.log('Failed to get cat picture');
  });
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendLocation(recipientId, location) {
  rapid.call('GoogleGeocodingAPI', 'addressToCoordinates', { 
    'address': location,
    'apiKey': 'INSERT'
  }).on('success', (payload)=>{
    console.log('Successfully get location: ' + location);
    var reply_str = '(' + payload.lat + ', ' + payload.lng + ')';
    sendTextMessage(recipientId, reply_str);
    var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: 'https://maps.googleapis.com/maps/api/staticmap?center=' + payload.lat + ',' + payload.lng + '&zoom=13&size=400x400'
        }
      }
    }
  };
  callSendAPI(messageData);
  }).on('error', (payload)=>{
    console.log('Failed to get location: ' + location);
    var reply_str = 'Failed to get ' + location;
    sendTextMessage(recipientId, reply_str)
  });
}

function handleGroup(recipientId, command, arg) {
  switch (command) {
    case 'create':
      console.log('Creating group ' + arg);
      var req_url = 'https://' + db_username + '.cloudant.com/group';
      var body_json = {
        "_id": arg,
        "name": arg,
        "members": [recipientId]
      };

      request({
        uri: req_url,
        headers: {
          'content-type': 'application/json',
          'authorization': 'Basic ' + DB_AUTH
        },
        method: 'POST',
        json: body_json

      }, function (error, response, body) {
        if (!error && response.statusCode == 201) {
          if (body.ok) {
            console.log("Successfully created group %s", arg);
            sendTextMessage(recipientId, "Successfully created group " + arg);
          } else {
            console.log("Failed to create group %s. %s", arg, body);
            sendTextMessage(recipientId, "Failed to create group " + arg);
          }
        } else if (!error && response.statusCode == 409) {
            console.log("Group %s already exist", arg);
            sendTextMessage(recipientId, 'Group ' + arg + ' already exists');
        } else {
          console.error("Failed calling DB API.", response.statusCode, response.statusMessage, body.error);
        }
      });
      break;

    case 'join':
      console.log('Joining group ' + arg);
      var req_url = 'https://' + db_username + '.cloudant.com/group/' + arg;

      // Get old rev
      request({
        uri: req_url,
        headers: {
          'authorization': 'Basic ' + DB_AUTH
        },
        method: 'GET'

      }, function (error, response, body) {
        var rev = undefined;
        var members = [];
        if (!error && response.statusCode == 200) {
          console.log('GET body', body)
          body_json = JSON.parse(body)
          rev = body_json["_rev"];
          members = body_json["members"];
          console.log("Successfully queried group %s", arg);
        } else {
          console.error("Failed calling DB GET API.", response.statusCode, response.statusMessage, body.error);
          return;
        }

        // Update document with user added
        console.log('members', members);
        if (members.indexOf(recipientId) < 0) {
          members.push(recipientId);
        } else {
          console.log("Already in group:", arg);
          sendTextMessage(recipientId, 'Already in group ' + arg);
          return;
        }

        console.log('_rev', rev);
        var body_json = {
          "_id": arg,
          "_rev": rev,
          "name": arg,
          "members": members
        };
        request({
          uri: req_url,
          headers: {
            'content-type': 'application/json',
            'authorization': 'Basic ' + DB_AUTH
          },
          method: 'PUT',
          json: body_json

        }, function (error, response, body) {
          if (!error && response.statusCode == 201) {
            if (body.ok) {
              console.log("Successfully joined group %s", arg);
              sendTextMessage(recipientId, "Successfully joined group " + arg);
            } else {
              console.log("Failed to join group %s. %s", arg, body);
              sendTextMessage(recipientId, "Failed to join group " + arg);
              return;
            }
          } else if (!error && response.statusCode == 409) {
              console.log("Failed to update group: %s", arg);
              sendTextMessage('Failed to update group: ' + arg);
          } else {
            console.error("Failed calling DB PUT API.", response.statusCode, response.statusMessage, body.error);
            return;
          }
        });
      });
      break;

    case 'leave':
      console.log("You can't leave the group: %s", arg);
      sendTextMessage("You can't leave the group: " + arg);
      break;

    default:
      sendTextMessage(recipientId, "Usage: @group [create|join|leave] <group_name>");

  }
}

function getLocation(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      "text":"Please share your location:",
      "quick_replies":[
        {
          "content_type":"location",
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function saveLocation(recipientId, lat, lng) {
  var req_url = 'https://' + db_username + '.cloudant.com/location/' + recipientId;

  request({
    uri: req_url,
    headers: {
      'authorization': 'Basic ' + DB_AUTH
    },
    method: 'GET'

  }, function (error, response, body) {
    var body_json;
    console.log("saveLocation body:", body);
    if (!error && response.statusCode == 200) {
      body_json = {
        "_id": recipientId,
        "_rev": JSON.parse(body)["_rev"],
        "lat": lat,
        "lng": lng
      };
      console.log("Successfully queried location");
    } else if (!error && response.statusCode == 404) {
      body_json = {
        "_id": recipientId,
        "lat": lat,
        "lng": lng
      };
    } else {
      console.error("Failed calling DB GET API.", response.statusCode, response.statusMessage, body.error);
      return;
    }

    // Update document with user added
    request({
      uri: req_url,
      headers: {
        'content-type': 'application/json',
        'authorization': 'Basic ' + DB_AUTH
      },
      method: 'PUT',
      json: body_json

    }, function (error, response, body) {
      if (!error && response.statusCode == 201) {
        if (body.ok) {
          console.log("Successfully updated location");
          sendTextMessage(recipientId, "Successfully updated location");
        } else {
          console.log("Failed to update location. %s", body);
          sendTextMessage(recipientId, "Failed to update location");
          return;
        }
      } else if (!error && response.statusCode == 409) {
          console.log("Failed to update location (bad rev)");
          sendTextMessage("Failed to update location (bad rev)");
      } else {
        console.error("Failed calling DB PUT API.", response.statusCode, response.statusMessage, body.error);
        return;
      }
    });
  });
}

function startTrip(recipientId, destination) {
  // Find nearest airport
  var req_url = 'https://' + db_username + '.cloudant.com/location/' + recipientId;

  request({
    uri: req_url,
    headers: {
      'authorization': 'Basic ' + DB_AUTH
    },
    method: 'GET'

  }, function (error, response, body) {
    var body_json, src_lat, src_lng;
    if (!error && response.statusCode == 200) {
        body_json = JSON.parse(body);
        src_lat = body_json['lat'];
        src_lng = body_json['lng'];
    } else if (!error && response.statusCode == 404) {
      sendTextMessage("No starting location set");
      return;
    } else {
      console.error("Failed calling DB GET API.", response.statusCode, response.statusMessage, body.error);
      return;
    }

    // Find destination coord
    rapid.call('GoogleGeocodingAPI', 'addressToCoordinates', { 
      'address': destination,
      'apiKey': 'INSERT'
    }).on('success', (payload)=>{
      console.log('Successfully get location: ' + destination);
      var dest_lat = payload.lat;
      var dest_lng = payload.lng;

      // Find source airport
      request({
        uri: 'https://api.sandbox.amadeus.com/v1.2/airports/nearest-relevant',
        qs: {
          apikey: 'INSERT',
          latitude: src_lat,
          longitude: src_lng
        },
        method: 'GET'
      }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
          body_json = JSON.parse(body);
          var src_airport_name = body_json[0]['airport'];
          var src_city_name = body_json[0]['city_name'];

          // Find destination airport
          request({
            uri: 'https://api.sandbox.amadeus.com/v1.2/airports/nearest-relevant',
            qs: {
              apikey: 'INSERT',
              latitude: dest_lat,
              longitude: dest_lng
            },
            method: 'GET'
          }, function (error, response, body) {
            if (!error && response.statusCode == 200) {
              body_json = JSON.parse(body);
              var dest_airport_name = body_json[0]['airport'];
              var dest_city_name = body_json[0]['city_name'];

              // Find cheapest ticket
              request({
                uri: 'https://api.sandbox.amadeus.com/v1.2/flights/low-fare-search',
                qs: {
                  apikey: 'INSERT',
                  origin: src_airport_name,
                  destination: dest_airport_name,
                  departure_date: '2016-11-25',
                  return_date: '2016-11-28',
                  nonstop: 'true',
                  number_of_results: '1'
                },
                method: 'GET'
              }, function(error, response, body) {
                if (!error && response.statusCode == 200) {
                  body_json = JSON.parse(body);
                  var passenger_info = [{
                    passenger_id: 'INSERT',
                    name: 'INSERT'
                  }];
                  var src_airport = {
                    airport_code: src_airport_name,
                    city: src_city_name
                  };
                  var dest_airport = {
                    airport_code: dest_airport_name,
                    city: dest_city_name
                  };
                  var flight_schedule_outbound = {
                    departure_time: body_json['results'][0]['itineraries'][0]['outbound']['flights'][0]['departs_at'],
                    arrival_time: body_json['results'][0]['itineraries'][0]['outbound']['flights'][0]['arrives_at']
                  };
                  var flight_info_outbound = {
                    connection_id: 'c01',
                    segment_id: 's01',
                    flight_number: body_json['results'][0]['itineraries'][0]['outbound']['flights'][0]['flight_number'],
                    aircraft_type: body_json['results'][0]['itineraries'][0]['outbound']['flights'][0]['aircraft'],
                    departure_airport: src_airport,
                    arrival_airport: dest_airport,
                    flight_schedule: flight_schedule_outbound,
                    travel_class: 'economy'
                  };
                  var flight_schedule_inbound = {
                    departure_time: body_json['results'][0]['itineraries'][0]['inbound']['flights'][0]['departs_at'],
                    arrival_time: body_json['results'][0]['itineraries'][0]['inbound']['flights'][0]['arrives_at']
                  };
                  var flight_info_inbound = {
                    connection_id: 'c02',
                    segment_id: 's02',
                    flight_number: body_json['results'][0]['itineraries'][0]['inbound']['flights'][0]['flight_number'],
                    aircraft_type: body_json['results'][0]['itineraries'][0]['inbound']['flights'][0]['aircraft'],
                    departure_airport: dest_airport,
                    arrival_airport: src_airport,
                    flight_schedule: flight_schedule_inbound,
                    travel_class: 'economy'
                  };
                  var total_price = body_json['results'][0]['fare']['total_price'];
                  var total_price_int = parseInt(total_price, 10);
                  var passenger_segment_info_outbound = {
                    segment_id: 's01',
                    passenger_id: 'p01',
                    seat: '20A',
                    seat_type: 'Economy',
                    product_info: "[{'title':'Air fare', 'value':" + (total_price_int / 2) + "}]"
                  };
                  var passenger_segment_info_inbound = {
                    segment_id: 'INSERT',
                    passenger_id: 'INSERT',
                    seat: 'INSERT',
                    seat_type: 'Economy',
                    product_info: "[{'title':'Air fare', 'value':" + (total_price_int / 2) + "}]"
                  };
                  var payload = {
                    template_type: 'airline_itinerary',
                    intro_message: "Here's your flight itinerary to " + destination,
                    locale: "en_US",
                    pnr_number: 'A7994C',
                    passenger_info: passenger_info,
                    flight_info: [flight_info_outbound, flight_info_inbound],
                    passenger_segment_info: [passenger_segment_info_outbound, passenger_segment_info_inbound],
                    total_price: total_price_int,
                    currency: 'USD'
                  };
                  var messageData = {
                    recipient: {
                      id: recipientId
                    },
                    message: {
                      attachment: {
                        type: 'template',
                        payload: payload
                      }
                    }
                  };
                  callSendAPI(messageData);
                }
              });
            } else {
              console.error("Failed to retrieve destination airport", response.statusCode, response.statusMessage, body.error);
              sendTextMessage(recipientId, "Failed to retrieve destination airport");
              return;
            }
          });
        } else {
          console.error("Failed to retrieve source airport", response.statusCode, response.statusMessage, body.error);
          sendTextMessage(recipientId, "Failed to retrieve source airport");
          return;
        }
      });
    }).on('error', (payload)=>{
      console.log('Failed to get location: ' + destination);
      var reply_str = 'Failed to get ' + destination;
      sendTextMessage(recipientId, reply_str);
      return;
    });
  });
}

function planMeet(recipientId, group_name, event_name, threshold) {
  var req_url = 'https://' + db_username + '.cloudant.com/group/' + group_name;
  var members = [];
  var body_json;
  request({
    uri: req_url,
    headers: {
      'authorization': 'Basic ' + DB_AUTH
    },
    method: 'GET'

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      body_json = JSON.parse(body)
      members = body_json["members"];
      console.log("Successfully queried group %s", group_name);

      // Get organizer name
      req_url = 'https://' + db_username + '.cloudant.com/person/' + recipientId;
      request({
        uri: req_url,
        headers: {
          'authorization': 'Basic ' + DB_AUTH
        },
        method: 'GET'
      }, function(error, response, body) {
        if (!error && response.statusCode == 200) {
          // Update document with user added
          body_json = JSON.parse(body);
          var orgnaizer_name = body_json['first_name'] + ' ' + body_json['last_name'];
          if (members.indexOf(recipientId) < 0) {
            console.log("User not in group:", group_name);
            sendTextMessage('You are not in group ' + group_name);
            return;
          } else {
            members.forEach(function(member){
              console.log("Contacting member", member);
              var messageData = {
                recipient: {
                  id: member
                },
                message: {
                  text: orgnaizer_name + ' has invited you to ' + event_name,
                  quick_replies: [
                    {
                      "content_type": "text",
                      "title": "Accept",
                      "payload": '{"type":"meet", "status":"accepted", "user":"' + member + '", "event":"' + event_name + '"}',
                      "image_url": "https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678134-sign-check-128.png"
                    },
                    {
                      "content_type": "text",
                      "title": "Decline",
                      "payload": '{"type":"meet", "status":"declined", "user":"' + member + '", "event":"' + event_name + '"}',
                      "image_url": "https://cdn3.iconfinder.com/data/icons/flat-actions-icons-9/792/Close_Icon_Dark-128.png"
                    }
                  ]
                }
              };
              callSendAPI(messageData);
            });
          }
        } else {
          console.error("Failed calling person DB GET API.", response.statusCode, response.statusMessage, body.error);
          return;
        }
      });
    } else {
      console.error("Failed calling group DB GET API.", response.statusCode, response.statusMessage, body.error);
      return;
    }
  });
}

function contactMembers(recipientId, quick_event_payload) {
  if (quick_event_payload['status'] == 'declined') {
    return;
  }

  var numbers = ['INSERT', 'INSERT'];
  const RapidAPI = require('rapidapi-connect');
  const rapid = new RapidAPI('jimbot', 'INSERT');

  numbers.forEach(function(number) {
    rapid.call('Twilio', 'sendSms', { 
      'accountSid': 'INSERT',
      'accountToken': 'INSERT',
      'from': 'INSERT',
      'messagingServiceSid': 'INSERT',
      'to': number,
      'body': '__Name__ has accepted invitation to ' + quick_event_payload['event'] + '. Your party is now full!'
    }).on('success', (payload)=>{
        console.log('Messages sent to group event', quick_event_payload['event']);
    }).on('error', (payload)=>{
        console.error('Twilio unable to send messages to ', quick_event_payload['event'], '. payload:', payload);
    });
  });
  sendTextMessage(recipientId, 'Party complete. Alert messages sent to group event ' + quick_event_payload['event']);
}

function recognizeLocation(recipientId, image_url) {
  var visual_recognition = watson.visual_recognition({
    api_key: 'INSERT',
    version: 'v3',
    version_date: '2016-05-20'
  });

  var params = {url : image_url};
  var results = '';

  visual_recognition.classify(params, function(err, res) {
  
    function between_quotes(str) {
        var quote_count = 0;
        var result = "";
        for (i = 1;i<str.length;i++){
            if (str[i] == '"')
                return result;
            result += str[i];
      
      }
      return null;
    }
    
    if (err) {
        console.log('err', err);
    } else {
      results = JSON.stringify(res, null, 2);
      console.log('image recognition results', res);
      var results_json = JSON.parse(results);
      var search_name = [results_json['images'][0]['classifiers'][0]['classes'][0]['class'],
                         results_json['images'][0]['classifiers'][0]['classes'][1]['class']];
      // while (search_name.length < 2) {
      //   if (results.indexOf('"class": ') >= 0) {
      //     var index = results.indexOf('"class": ');
      //     results = results.substring((index + 9),results.length);
      //     search_name = search_name.concat(between_quotes(results));
      //   }
      // }
      var string_search_name = '';
      for(var i = 0; i < search_name.length; i++) {
        if (i == 0) {
          string_search_name = search_name[i];
        } else {
          string_search_name = string_search_name + ' ' + search_name[i];
        }
      }
      console.log('Recognized location as', string_search_name);

      // Do geo search on recognized name
      sendTextMessage(recipientId, 'Location detected as ' + string_search_name + '. Initiating trip planner.');
      startTrip(recipientId, string_search_name);
    }
  });
}
