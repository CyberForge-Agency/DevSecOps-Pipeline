import crypto from "crypto";
import { RequestHandler, Request, Response, Router } from "express";

interface Item {
  id: string;
  name: string;
  createdAt: string;
}

/**
 * Minimal capacity-limited store interface the router depends on.
 * Production injects a BoundedMap; tests can inject a fresh instance per suite.
 */
interface ItemStore {
  get(id: string): Item | undefined;
  has(id: string): boolean;
  set(id: string, value: Item): void;
  delete(id: string): boolean;
  values(): IterableIterator<Item>;
}

/**
 * A Map that never exceeds `capacity` entries. When a new key is added beyond
 * capacity, the oldest entry (insertion order) is evicted. This caps memory so
 * the public, unauthenticated demo API cannot be flooded to OOM.
 */
class BoundedMap implements ItemStore {
  private readonly store = new Map<string, Item>();

  constructor(private readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new Error("BoundedMap capacity must be a positive integer");
    }
  }

  get size(): number {
    return this.store.size;
  }

  get(id: string): Item | undefined {
    return this.store.get(id);
  }

  has(id: string): boolean {
    return this.store.has(id);
  }

  set(id: string, value: Item): void {
    if (!this.store.has(id) && this.store.size >= this.capacity) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) {
        this.store.delete(oldest);
      }
    }
    this.store.set(id, value);
  }

  delete(id: string): boolean {
    return this.store.delete(id);
  }

  values(): IterableIterator<Item> {
    return this.store.values();
  }
}

const DEFAULT_CAPACITY = 1000;

/** No-op middleware used when no rate limiter is injected (e.g. in unit tests). */
const passThrough: RequestHandler = (_req, _res, next) => next();

/**
 * Build an items router backed by an injected store. Removing the module-level
 * singleton gives an injection seam: production wires a bounded store, tests
 * build an isolated store per suite (no shared global mutable state).
 *
 * An optional `mutationLimiter` is applied only to the mutating routes
 * (POST/DELETE) so read traffic and other endpoints stay unthrottled.
 */
function createItemsRouter(
  store: ItemStore = new BoundedMap(DEFAULT_CAPACITY),
  mutationLimiter: RequestHandler = passThrough,
): Router {
  const router = Router();

  router.get("/", (_req: Request, res: Response) => {
    res.json(Array.from(store.values()));
  });

  router.post("/", mutationLimiter, (req: Request, res: Response) => {
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

    store.set(item.id, item);
    res.status(201).json(item);
  });

  router.get("/:id", (req: Request, res: Response) => {
    const item = store.get(req.params.id);
    if (!item) {
      res.status(404).json({ error: "item not found" });
      return;
    }

    res.json(item);
  });

  router.delete("/:id", mutationLimiter, (req: Request, res: Response) => {
    if (!store.has(req.params.id)) {
      res.status(404).json({ error: "item not found" });
      return;
    }

    store.delete(req.params.id);
    res.status(204).send();
  });

  return router;
}

export { BoundedMap, createItemsRouter, DEFAULT_CAPACITY };
export type { Item, ItemStore };
