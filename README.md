# Go Server Template

This is a resful API server for this project.

## Project structure

### models
This folder contains the models for the database.

### routes
This folder contains the routes for the API.

### middleware
This folder contains the middleware for the API.

### controllers
This folder contains the controllers for the API.

### database
This folder contains the database connection.

### initializers
This folder contains the initializers for the server.

### utils
This folder contains utility functions.

### app.go
This is the main file for the server.

## Setup
To setup the server, you need to have a `.env` file in the root directory of the project. The `.env` file should contain the following variables:

```
PORT=3000
POSTGRES_URI=postgres://username:password@localhost:5432/dbname
JWT_SECRET=secret-32-characters-long
APP_ENV=dev || prod
```

After setting up the run the following command to setup the go modules:

```
go mod tidy
```

To start the server, run the following command:

```
go run app.go
```
