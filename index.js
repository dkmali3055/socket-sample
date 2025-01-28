const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { StreamChat } = require("stream-chat");
const app = express();
const server = http.createServer(app);
const dotenv = require("dotenv");
dotenv.config();

const mongoose = require("mongoose");
const { ObjectId } = mongoose.Types;
const { AvatarGenerator } = require("random-avatar-generator");
const { StreamClient } = require("@stream-io/node-sdk");

const apiKey = process.env.STREAM_API_KEY;
const secretKey = process.env.STREAM_API_SECRET;

client = new StreamClient(apiKey, secretKey);
// parse json request body
app.use(express.json());

// parse urlencoded request body
app.use(express.urlencoded({ extended: true }));
// const io = new Server(server);

// Socket connection
// io.on('connection', (socket) => {
//     let { id } = socket.handshake.query
//     console.log(`User connected: ${id}`);
//     socket.user= id
//     socket.join(id);
//     socket.on('send_message', (data) => {
//     console.log(`message received from ${socket.user},  ${data.message}`);

//     // Emit call-connected event
//     // io.to("123").emit('receive_message', { message : data.message })
//     // io.to('xyz').emit('receive_message', { message : data.message })
//     io.sockets.emit('receive_message', { message : data.message });
//   });
//   // Handle receivedCall event
//   socket.on('received-call', (data) => {
//     console.log(`Call received from ${socket.id}`);

//     // Emit call-connected event
//     socket.emit('call-connected', { id : socket.id });
//   });

//   // Handle responseCall event
//     socket.on('response-call', (data) => {
//     console.log(`Response received for call from ${socket.id}`);

//     if (data.response === 'accepted') {
//         // Emit acceptedCall event if call is accepted
//         socket.emit('accepted-call', { id : socket.id });
//     } else if (data.response === 'rejected') {
//         // Emit rejectedCall event if call is rejected
//         socket.emit('rejected-call', { id : socket.id });
//     }
//     });

//   // Handle disconnect event
//   socket.on('disconnect', () => {
//     console.log(`User disconnected: ${socket.user}`);
//   });
// });
const generateToken = (userId) => {
  // Initialize the StreamChat client
  const client = new StreamChat(apiKey, secretKey);

  // Generate token for a user
  const token = client.createToken(userId); // The token is generated for the specified userId
  return token;
};
app.post("/get-token", (req, res) => {
  console.log(req.body);
  const { userId } = req.body;
  console.log("🚀 ~ app.post ~ userId:", userId);

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    const token = generateToken(userId);
    res.json({ token, apiKey });
  } catch (error) {
    console.error("Error generating token:", error);
    res.status(500).json({ error: "Failed to generate token" });
  }
});

const createObjectId = (id) => {
  let objId;
  if (id && id != "") {
    if (!ObjectId.isValid(id)) {
      throw new Error("Given id is not valid");
    }
    if (id instanceof ObjectId) objId = id;
    else objId = ObjectId.createFromHexString(id);
  } else {
    objId = new ObjectId();
  }
  return objId;
};

const generator = new AvatarGenerator();
app.post("/create-user", async (req, res) => {
  try {
    const { userId, username } = req.body;
    console.log("🚀 ~ app.post create-user ~ req.body:", req.body);
    const newUser = {
      id: typeof userId === "string" ? userId : userId.toString(),
      role: "user",
      name: username,
      image: generator.generateRandomAvatar(),
    };
    const user = await client.upsertUsers([newUser]);
    console.log("🚀 ~ app.post ~ user:", user);
    res.json({ user });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(400).json({
      message: error.message,
    });
  }
});
app.post("/notification", (req, res) => {
  const body = req.body;
  console.log("🚀 ~ app.post ~ body:", JSON.stringify(body));
  res.status(200).send("OK");
});
// Start the server
server.listen(process.env.PORT || 4050, () => {
  console.log("Server listening on port 4050");
});
