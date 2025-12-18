const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
const ImageKit = require("@imagekit/nodejs");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 5000;

// const serviceAccount = require("./chef-origin-firebase-adminsdk-fbsvc-c80020aecc.json");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware
app.use(
  cors({
    origin: [process.env.SITE_DOMAIN, "http://localhost:5174"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ message: "Unauthorized access" });
  }
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).send({ message: "Unauthorized access" });
  }
};

// Image Kit configuration

const imgkitClient = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
});

// allow cross-origin requests
// app.use(function (req, res, next) {
//   res.header("Access-Control-Allow-Origin", "*");
//   res.header(
//     "Access-Control-Allow-Headers",
//     "Origin, X-Requested-With, Content-Type, Accept"
//   );
//   next();
// });

app.get("/auth", function (req, res) {
  // Your application logic to authenticate the user
  // For example, you can check if the user is logged in or has the necessary permissions
  // If the user is not authenticated, you can return an error response
  const { token, expire, signature } =
    imgkitClient.helper.getAuthenticationParameters();
  res.send({
    token,
    expire,
    signature,
    publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  });
});

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.dojua2g.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;

async function run() {
  try {
    // Connect the client to the server
    // await client.connect();

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );

    // Set database
    db = client.db("chef_origin");

    // Verify Admin Middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.user.email;
      const query = { email: email };
      const user = await db.collection("users").findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    // Verify Chef Middleware
    const verifyChef = async (req, res, next) => {
      const email = req.user.email;
      const query = { email: email };
      const user = await db.collection("users").findOne(query);
      const isChef = user?.role === "chef";
      if (!isChef) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    // ==================== AUTH ENDPOINTS ====================
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      // console.log("user for token", user);
      const token = user?.token; // Expecting { token: "..." } from client
      if (!token) {
        return res.status(400).send({ message: "Token is required" });
      }
      try {
        // Verify the token
        const decodedToken = await admin.auth().verifyIdToken(token);

        // Set cookie
        res
          .cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          })
          .send({ success: true });
      } catch (error) {
        console.error("Error verifying token:", error);
        res.status(401).send({ success: false, message: "Unauthorized" });
      }
    });

    app.post("/logout", (req, res) => {
      res
        .clearCookie("token", {
          maxAge: 0,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    // ==================== USERS ENDPOINTS ====================
    // Get all users
    app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const users = await db.collection("users").find().toArray();
        res.json(users);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get user by ID
    app.get("/api/users/:id", verifyToken, async (req, res) => {
      try {
        const user = await db
          .collection("users")
          .findOne({ uid: req.params.id });
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }
        res.json(user);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Create user
    app.post("/api/users", verifyToken, async (req, res) => {
      try {
        const { uid, name, email, photoURL, address, role, status } = req.body;

        // Check if user already exists
        const existingUser = await db.collection("users").findOne({ uid });
        if (existingUser) {
          return res.status(400).json({ error: "User already exists" });
        }

        const newUser = {
          uid,
          name,
          email,
          photoURL,
          address,
          role: role || "user",
          status: status || "active",
          createdAt: new Date(),
        };

        const result = await db.collection("users").insertOne(newUser);
        res.status(201).json({ ...newUser, _id: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Update user
    app.put("/api/users/:id", verifyToken, async (req, res) => {
      try {
        const { name, photoURL, address, role, status } = req.body;
        const id = req.params.id;
        let query = { uid: id };

        if (ObjectId.isValid(id)) {
          query = { $or: [{ uid: id }, { _id: new ObjectId(id) }] };
        }

        const result = await db.collection("users").updateOne(query, {
          $set: {
            ...(name && { name }),
            ...(photoURL && { photoURL }),
            ...(address && { address }),
            ...(role && { role }),
            ...(status && { status }),
            updatedAt: new Date(),
          },
        });

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        res.json({ message: "User updated successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== MEALS ENDPOINTS ====================
    // Get all meals
    app.get("/api/meals", async (req, res) => {
      try {
        const limit = req.query.limit ? parseInt(req.query.limit) : 0;
        const meals = await db
          .collection("meals")
          .find()
          .limit(limit)
          .toArray();
        res.json(meals);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get meal by ID
    app.get("/api/meals/:id", async (req, res) => {
      try {
        const meal = await db
          .collection("meals")
          .findOne({ _id: new ObjectId(req.params.id) });
        if (!meal) {
          return res.status(404).json({ error: "Meal not found" });
        }
        res.json(meal);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Create meal
    app.post("/api/meals", verifyToken, verifyChef, async (req, res) => {
      try {
        const {
          foodName,
          chefName,
          foodImage,
          price,
          rating,
          ingredients,
          estimatedDeliveryTime,
          chefExperience,
          chefId,
          userEmail,
          deliveryArea,
        } = req.body;

        const newMeal = {
          foodName,
          chefName,
          foodImage,
          price: parseFloat(price),
          rating: parseFloat(rating) || 0,
          ingredients: Array.isArray(ingredients) ? ingredients : [ingredients],
          estimatedDeliveryTime,
          chefExperience,
          chefId,
          userEmail,
          deliveryArea,
          createdAt: new Date(),
        };

        const result = await db.collection("meals").insertOne(newMeal);
        res.status(201).json({ ...newMeal, _id: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Update meal
    app.put("/api/meals/:id", verifyToken, async (req, res) => {
      try {
        const {
          foodName,
          chefName,
          foodImage,
          price,
          rating,
          ingredients,
          estimatedDeliveryTime,
          chefExperience,
          deliveryArea,
        } = req.body;

        const result = await db.collection("meals").updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              ...(foodName && { foodName }),
              ...(chefName && { chefName }),
              ...(foodImage && { foodImage }),
              ...(price && { price: parseFloat(price) }),
              ...(rating && { rating: parseFloat(rating) }),
              ...(ingredients && { ingredients }),
              ...(estimatedDeliveryTime && { estimatedDeliveryTime }),
              ...(chefExperience && { chefExperience }),
              ...(deliveryArea && { deliveryArea }),
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Meal not found" });
        }

        res.json({ message: "Meal updated successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Delete meal
    app.delete("/api/meals/:id", verifyToken, async (req, res) => {
      try {
        const result = await db.collection("meals").deleteOne({
          _id: new ObjectId(req.params.id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Meal not found" });
        }

        res.json({ message: "Meal deleted successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== REVIEWS ENDPOINTS ====================
    // Get all reviews
    app.get("/api/reviews", async (req, res) => {
      try {
        const limit = req.query.limit ? parseInt(req.query.limit) : 0;
        const email = req.query.email;

        let matchStage = {};
        if (email) {
          matchStage = { reviewerEmail: email };
        }

        const pipeline = [
          { $match: matchStage },
          {
            $addFields: {
              foodIdObj: { $toObjectId: "$foodId" },
            },
          },
          {
            $lookup: {
              from: "meals",
              localField: "foodIdObj",
              foreignField: "_id",
              as: "mealDetails",
            },
          },
          {
            $unwind: {
              path: "$mealDetails",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $addFields: {
              mealName: "$mealDetails.foodName",
              mealImage: "$mealDetails.foodImage",
            },
          },
          {
            $project: {
              mealDetails: 0,
              foodIdObj: 0,
            },
          },
        ];

        if (limit > 0) {
          pipeline.push({ $limit: limit });
        }

        const reviews = await db
          .collection("reviews")
          .aggregate(pipeline)
          .toArray();
        res.json(reviews);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get reviews for a meal
    app.get("/api/meals/:id/reviews", async (req, res) => {
      try {
        const reviews = await db
          .collection("reviews")
          .find({ foodId: req.params.id })
          .toArray();
        res.json(reviews);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Create review
    app.post("/api/reviews", verifyToken, async (req, res) => {
      try {
        const {
          foodId,
          reviewerName,
          reviewerEmail,
          reviewerImage,
          rating,
          comment,
        } = req.body;

        const newReview = {
          foodId,
          reviewerName,
          reviewerEmail,
          reviewerImage,
          rating: parseInt(rating),
          comment,
          date: new Date(),
        };

        const result = await db.collection("reviews").insertOne(newReview);
        res.status(201).json({ ...newReview, _id: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Update review
    app.put("/api/reviews/:id", verifyToken, async (req, res) => {
      try {
        const { rating, comment } = req.body;

        const result = await db.collection("reviews").updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              ...(rating && { rating: parseInt(rating) }),
              ...(comment && { comment }),
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Review not found" });
        }

        res.json({ message: "Review updated successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Delete review
    app.delete("/api/reviews/:id", verifyToken, async (req, res) => {
      try {
        const result = await db.collection("reviews").deleteOne({
          _id: new ObjectId(req.params.id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Review not found" });
        }

        res.json({ message: "Review deleted successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== FAVORITES ENDPOINTS ====================
    // Get user favorites
    app.get("/api/favorites/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (req.user.email !== email) {
        res.clearCookie("token", {
          maxAge: 0,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });
        return res.status(403).send({ message: "forbidden access" });
      }
      try {
        const favorites = await db
          .collection("favorites")
          .find({ userEmail: email })
          .toArray();
        res.json(favorites);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Add to favorites
    app.post("/api/favorites", verifyToken, async (req, res) => {
      try {
        const { userEmail, mealId, mealName, chefId, chefName, price } =
          req.body;

        const favorite = {
          userEmail,
          mealId,
          mealName,
          chefId,
          chefName,
          price,
          addedTime: new Date(),
        };

        const result = await db.collection("favorites").insertOne(favorite);
        res.status(201).json({ ...favorite, _id: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Remove from favorites
    app.delete("/api/favorites/:id", verifyToken, async (req, res) => {
      try {
        const result = await db.collection("favorites").deleteOne({
          _id: new ObjectId(req.params.id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ error: "Favorite not found" });
        }

        res.json({ message: "Favorite removed successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== ORDERS ENDPOINTS ====================
    // Get all orders
    app.get("/api/orders", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const orders = await db.collection("orders").find().toArray();
        res.json(orders);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get user orders
    app.get("/api/orders/user/:email", verifyToken, async (req, res) => {
      const email = req.params.email;
      if (req.user.email !== email) {
        res.clearCookie("token", {
          maxAge: 0,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });
        return res.status(403).send({ message: "forbidden access" });
      }
      try {
        const orders = await db
          .collection("orders")
          .aggregate([
            { $match: { userEmail: email } },
            {
              $addFields: {
                foodIdObj: { $toObjectId: "$foodId" },
              },
            },
            {
              $lookup: {
                from: "meals",
                localField: "foodIdObj",
                foreignField: "_id",
                as: "mealDetails",
              },
            },
            {
              $unwind: {
                path: "$mealDetails",
                preserveNullAndEmptyArrays: true,
              },
            },
            {
              $addFields: {
                chefName: { $ifNull: ["$chefName", "$mealDetails.chefName"] },
                deliveryTime: {
                  $ifNull: [
                    "$deliveryTime",
                    "$mealDetails.estimatedDeliveryTime",
                  ],
                },
              },
            },
            {
              $project: {
                mealDetails: 0,
                foodIdObj: 0,
              },
            },
          ])
          .toArray();
        res.json(orders);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get chef orders
    app.get("/api/orders/chef/:chefId", verifyToken, async (req, res) => {
      try {
        const orders = await db
          .collection("orders")
          .find({ chefId: req.params.chefId })
          .toArray();
        res.json(orders);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Create order
    app.post("/api/orders", verifyToken, async (req, res) => {
      try {
        const {
          foodId,
          mealName,
          price,
          quantity,
          chefId,
          chefName,
          deliveryTime,
          userEmail,
          userAddress,
        } = req.body;

        const newOrder = {
          foodId,
          mealName,
          price: parseFloat(price),
          quantity: parseInt(quantity),
          chefId,
          chefName,
          deliveryTime,
          paymentStatus: "Pending",
          userEmail,
          userAddress,
          orderStatus: "pending",
          orderTime: new Date(),
        };

        const result = await db.collection("orders").insertOne(newOrder);
        res.status(201).json({ ...newOrder, _id: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Update order status
    app.put("/api/orders/:id/status", verifyToken, async (req, res) => {
      try {
        const { orderStatus } = req.body;

        const result = await db.collection("orders").updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              orderStatus,
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ error: "Order not found" });
        }

        res.json({ message: "Order status updated successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== PAYMENT ENDPOINTS ====================
    // Create Checkout Session
    app.post("/create-checkout-session", verifyToken, async (req, res) => {
      try {
        const { orderId } = req.body;
        const order = await db
          .collection("orders")
          .findOne({ _id: new ObjectId(orderId) });

        if (!order) {
          return res.status(404).json({ error: "Order not found" });
        }

        const sessionConfig = {
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: order.mealName,
                },
                unit_amount: Math.round(order.price * 100), // Amount in cents
              },
              quantity: order.quantity,
            },
          ],
          mode: "payment",
          success_url: `${process.env.SITE_DOMAIN}/payment/success?session_id={CHECKOUT_SESSION_ID}&orderId=${orderId}`,
          cancel_url: `${process.env.SITE_DOMAIN}/dashboard/orders`,
          metadata: {
            orderId: orderId,
            userEmail: order.userEmail,
          },
        };

        if (order.userEmail) {
          sessionConfig.customer_email = order.userEmail;
        }

        const session = await stripe.checkout.sessions.create(sessionConfig);

        res.json({ url: session.url, sessionId: session.id });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Payment Success
    app.post("/api/payment/success", verifyToken, async (req, res) => {
      try {
        const { sessionId, orderId } = req.body;
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status === "paid") {
          // Use orderId from metadata if available, otherwise fallback to request body
          const finalOrderId = session.metadata?.orderId || orderId;

          const paymentRecord = {
            orderId: finalOrderId,
            transactionId: sessionId,
            amount: session.amount_total / 100,
            currency: session.currency,
            paymentStatus: "paid",
            date: new Date(),
          };

          const paymentResult = await db
            .collection("payments")
            .insertOne(paymentRecord);

          const updateResult = await db.collection("orders").updateOne(
            { _id: new ObjectId(finalOrderId) },
            {
              $set: {
                paymentStatus: "paid",
                transactionId: sessionId,
              },
            }
          );

          res.json({
            success: true,
            paymentId: paymentResult.insertedId,
            metadata: session.metadata,
            amount: session.amount_total / 100,
            currency: session.currency,
          });
        } else {
          res.status(400).json({ error: "Payment not verified" });
        }
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== REQUESTS ENDPOINTS ====================
    // Get all requests
    app.get("/api/requests", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const requests = await db.collection("requests").find().toArray();
        res.json(requests);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Create request
    app.post("/api/requests", verifyToken, async (req, res) => {
      try {
        const { userName, userEmail, requestType } = req.body;

        const newRequest = {
          userName,
          userEmail,
          requestType, // "chef" or "admin"
          requestStatus: "pending", // "pending", "approved", "rejected"
          requestTime: new Date(),
        };

        const result = await db.collection("requests").insertOne(newRequest);
        res.status(201).json({ ...newRequest, _id: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Update request status
    app.put("/api/requests/:id", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const { requestStatus, newRole } = req.body;

        // Update request
        await db.collection("requests").updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              requestStatus,
              updatedAt: new Date(),
            },
          }
        );

        // If approved, update user role
        if (requestStatus === "approved") {
          const request = await db.collection("requests").findOne({
            _id: new ObjectId(req.params.id),
          });

          const chefId =
            request.requestType === "chef"
              ? `chef-${Math.floor(1000 + Math.random() * 9000)}`
              : null;

          await db.collection("users").updateOne(
            { email: request.userEmail },
            {
              $set: {
                role: newRole || request.requestType,
                ...(chefId && { chefId }),
              },
            }
          );
        }

        res.json({ message: "Request updated successfully" });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== STATISTICS ENDPOINTS ====================
    // Get statistics
    app.get("/api/statistics", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const totalUsers = await db.collection("users").countDocuments();
        const totalOrders = await db.collection("orders").countDocuments();
        const pendingOrders = await db
          .collection("orders")
          .countDocuments({ orderStatus: "pending" });
        const deliveredOrders = await db
          .collection("orders")
          .countDocuments({ orderStatus: "delivered" });

        // Calculate total payment
        const paymentResult = await db
          .collection("orders")
          .aggregate([
            {
              $group: {
                _id: null,
                totalPayment: {
                  $sum: { $multiply: ["$price", "$quantity"] },
                },
              },
            },
          ])
          .toArray();

        const totalPayment = paymentResult[0]?.totalPayment || 0;

        res.json({
          totalPayment,
          totalUsers,
          totalOrders,
          pendingOrders,
          deliveredOrders,
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ==================== HEALTH CHECK ====================
    app.get("/", (req, res) => {
      res.send("Chef Origin API is running!");
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Chef Origin server listening on port ${port}`);
});
