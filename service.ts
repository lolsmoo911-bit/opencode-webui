import node from "@prisma/composer/node";
import { secretString } from "@prisma/composer/arktype";
import { compute } from "@prisma/composer-prisma-cloud";
import { type } from "arktype";

const webuiInput = type({
  password: secretString(),
});

export default compute({
  name: "opencode-webui",
  deps: {},
  input: webuiInput,
  build: node({ module: import.meta.url, entry: "./dist/server.mjs" }),
});
