const express = require("express");
const http = require("http");
const dotenv = require("dotenv");
const { StreamClient } = require("@stream-io/node-sdk");
const { AvatarGenerator } = require("random-avatar-generator");
const mongoose = require("mongoose");

dotenv.config();

const app = express();
const server = http.createServer(app);

// Environment variables
const apiKey = process.env.STREAM_API_KEY;
const secretKey = process.env.STREAM_API_SECRET;

// Initialize Stream Video client
const videoClient = new StreamClient(apiKey, secretKey, { timeout: 3000 });

// Avatar generator for random avatars
const generator = new AvatarGenerator();

// Middleware to parse JSON and URL-encoded request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Utility to validate ObjectId
const { ObjectId } = mongoose.Types;
const createObjectId = (id) => {
  if (!id || id === "") {
    return new ObjectId();
  }
  if (!ObjectId.isValid(id)) {
    throw new Error("Given id is not valid");
  }
  return id instanceof ObjectId ? id : ObjectId.createFromHexString(id);
};

// Endpoint: Create a user for video/voice calling
app.post("/create-user", async (req, res) => {
  try {
    const { userId, username } = req.body;
    console.log("🚀 ~ app.post create-user ~ req.body:", req.body);

    if (!userId || !username) {
      return res
        .status(400)
        .json({ error: "User ID and username are required" });
    }

    const newUser = {
      id: typeof userId === "string" ? userId : userId.toString(),
      role: "user", // Adjust role if needed
      name: username,
      image: generator.generateRandomAvatar(),
    };

    // Create or update the user in Stream Video
    await videoClient.upsertUsers([newUser]);

    console.log("User successfully created in Stream Video:", newUser);
    res.json({ user: newUser });
  } catch (error) {
    console.error("Error creating user for video calling:", error);
    res.status(500).json({
      message: "Failed to create user",
      error: error.message,
    });
  }
});

// Endpoint: Generate a user token for authentication
const generateToken = (userId) => {
  try {
    return videoClient.createToken(userId);
  } catch (error) {
    console.error("Error generating token:", error);
    throw new Error("Failed to generate token");
  }
};

app.post("/get-token", (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }

    const token = generateToken(userId);
    res.json({ token, apiKey });
  } catch (error) {
    res.status(500).json({ error: "Failed to generate token" });
  }
});

// Endpoint: Handle incoming notifications (optional, for webhook integration)
app.post("/notification", (req, res) => {
  console.log("Received notification:", JSON.stringify(req.body));
  res.status(200).send("OK");
});

// Start the server
const PORT = process.env.PORT || 4050;
server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
