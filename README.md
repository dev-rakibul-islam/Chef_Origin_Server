# Chef Origin (Server)

## Purpose

The Chef Origin Server is the backend API that powers the Chef Origin platform. It handles data management, authentication, payment processing, and business logic. Built with Node.js and Express, it connects the client application to a MongoDB database and integrates with third-party services like Firebase, Stripe, and ImageKit.

## Live URL

- **Server:** https://chef-origin-server.vercel.app

## Key Features

- **RESTful API:** Comprehensive set of endpoints for Users, Meals, Orders, Reviews, and Requests.
- **Secure Authentication:** Middleware for verifying Firebase ID tokens and managing JWT cookies.
- **Role-Based Access Control (RBAC):** Custom middleware to protect routes and ensure only authorized users (Admins, Chefs) can access specific endpoints.
- **Database Management:** Efficient data storage and retrieval using MongoDB.
- **Payment Processing:** Secure payment intent creation and webhook handling via Stripe.
- **Image Management:** Integration with ImageKit for server-side image handling and authentication parameters.
- **Order Management:** Logic for creating orders, updating statuses, and tracking delivery.
- **Statistics:** Aggregation pipelines to calculate platform metrics (total users, orders, revenue).

## NPM Packages Used

- **Framework:** `express`
- **Database:** `mongodb`
- **Authentication:** `firebase-admin`
- **Payment:** `stripe`
- **Image Handling:** `@imagekit/nodejs`
- **Utilities:** `dotenv`, `cors`, `cookie-parser`

## Getting Started

1.  Clone the repository.
2.  Install dependencies: `npm install`
3.  Set up environment variables in a `.env` file:
    - `PORT`
    - `DB_USERNAME`, `DB_PASSWORD`
    - `STRIPE_SECRET_KEY`
    - `FB_SERVICE_KEY` (Base64 encoded Firebase Service Account)
    - `IMAGEKIT_PUBLIC_KEY`, `IMAGEKIT_PRIVATE_KEY`, `IMAGEKIT_URL_ENDPOINT`
    - `SITE_DOMAIN`
4.  Run the server: `npm start`
