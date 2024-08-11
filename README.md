# Social Media App

A full-featured social media application built using Node.js, Express, and MongoDB. This app allows users to register, login, create posts, comment on posts, and follow other users. It also supports profile management and displays users' posts with comments and likes.

## Features

- **User Authentication**: Register and login with JWT-based authentication.
- **Create Posts**: Users can create posts with a title, description, and image.
- **Comments**: Users can comment on posts, with comments being displayed along with the username and profile picture of the commenter.
- **Follow System**: Users can follow each other and see updates from users they follow.
- **Responsive API**: Built with REST principles and designed to be easily integrated with any frontend.

## Technologies Used

- **Backend**: Node.js, Express.js
- **Database**: MongoDB with Mongoose ORM
- **Authentication**: JWT (JSON Web Tokens)
- **File Uploads**: Multer for handling image uploads
- **Environment Variables**: Managed using `.env` file

## API Endpoints

### User

- **POST** `/api/v1/register`: Register a new user
- **POST** `/api/v1/login`: Login a user

### Post

- **POST** `/api/v1/post`: Create a new post
- **GET** `/api/v1/posts`: Get all posts
- **GET** `/api/v1/post/:postId`: Get a single post by ID, with comments and populated user info
- **DELETE** `/api/v1/post/:postId`: Delete a post by ID
- **POST** `/api/v1/post/:postId/comment`: Add a comment to a post
- **POST** `/api/v1/post/:postId/:userId/like`: Like a post

### Follow

- **POST** `/api/v1/user/:userId/follow`: Follow a user
- **POST** `/api/v1/user/:userId/unfollow`: Unfollow a user
- **GET** `/api/v1/user/:userId/followers`: Get followers of a user

[See full api documentation](https://documenter.getpostman.com/view/33550472/2sA3s3HWrj)
## Installation and Setup

### Prerequisites

- [Node.js](https://nodejs.org/en/) (v14+)
- [MongoDB](https://www.mongodb.com/) (Ensure MongoDB is running locally or provide a MongoDB URI)

### Setup Instructions

1. **Clone the repository**

    ```bash
    git clone git@github.com:musjib999/benmo_challange_api.git
    cd benmo_challange_api
    ```

2. **Install dependencies**

    ```bash
    npm install
    ```

3. **Configure environment variables**

    Create a `.env` file in the root of the project and add the following:

    ```bash
    APP_PORT=3000
    MONGO_URI=mongodb://localhost:27017/socialmedia
    JWT_SECRET=e3d639f5a0a4c1f1c9cfa1d9b302bb7cc0308b24df2433091b9d506e9bb6369f
    ```

4. **Start the application**

    Simply run:

    ```bash
    npm start
    ```

5. **Access the API**

    The API will be running on [http://localhost:3000](http://localhost:3000).
