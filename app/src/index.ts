import { app } from "./app";

const port = Number(process.env.PORT) || 3000;

app.listen(port, () => {
  // Minimal runtime log for smoke tests and local debugging.
  console.log(`Server running on port ${port}`);
});
