require("dotenv").config();
import "reflect-metadata";
import express from "express";
import { createConnection } from "typeorm";
import { User } from "./entities/User";
import { Post } from "./entities/Post";
import { ApolloServer } from "apollo-server-express";
import { buildSchema } from "type-graphql";
import { HelloResolver } from "./ resolvers/hello";
import { ApolloServerPluginLandingPageGraphQLPlayground } from "apollo-server-core";
import { UserResolver } from "./ resolvers/user";
const main = async () => {
  await createConnection({
    type: "postgres",
    database: "reddit",
    username: process.env.DB_USERNAME_DEV,
    password: process.env.DB_PASSWORD_DEV,
    logging: true,
    synchronize: true,
    entities: [User, Post],
  });
  const app = express();

  const apolloServer = new ApolloServer({
    schema: await buildSchema({
      resolvers: [HelloResolver, UserResolver],
      validate: false,
    }),
    plugins: [ApolloServerPluginLandingPageGraphQLPlayground],
  });
  await apolloServer.start();
  apolloServer.applyMiddleware({ app, cors: false });

  const PORT = process.env.PORT || 4000;

  app.listen(4000, () =>
    console.log(
      `server started on port ${PORT}. Graphql server started on http://localhost:${PORT}${apolloServer.graphqlPath}`
    )
  );
};
main().catch((error) => console.log(error));
