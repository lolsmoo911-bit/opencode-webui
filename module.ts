import { module } from "@prisma/composer";
import { envSecret } from "@prisma/composer-prisma-cloud";
import webui from "./service.ts";

export default module("opencode-webui", ({ provision }) => {
  provision(webui, {
    id: "webui",
    input: {
      password: envSecret("WEBUI_PASSWORD"),
    },
  });
});
