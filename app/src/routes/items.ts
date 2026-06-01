import crypto from "crypto";
import { Request, Response, Router } from "express";

interface Item {
  id: string;
  name: string;
  createdAt: string;
}

const items: Map<string, Item> = new Map();
const router = Router();

router.get("/", (_req: Request, res: Response) => {
  res.json(Array.from(items.values()));
});

router.post("/", (req: Request, res: Response) => {
  const { name } = req.body as { name?: unknown };
  if (!name || typeof name !== "string") {
    res.status(400).json({ error: "name is required" });
    return;
  }

  const item: Item = {
    id: crypto.randomUUID(),
    name,
    createdAt: new Date().toISOString(),
  };

  items.set(item.id, item);
  res.status(201).json(item);
});

router.get("/:id", (req: Request, res: Response) => {
  const item = items.get(req.params.id);
  if (!item) {
    res.status(404).json({ error: "item not found" });
    return;
  }

  res.json(item);
});

router.delete("/:id", (req: Request, res: Response) => {
  if (!items.has(req.params.id)) {
    res.status(404).json({ error: "item not found" });
    return;
  }

  items.delete(req.params.id);
  res.status(204).send();
});

export { items, router as itemsRouter };
