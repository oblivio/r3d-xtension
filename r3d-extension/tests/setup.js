/**
 * Vitest setup — bootstraps globalThis.__R3D and stubs browser APIs
 * so lib modules can be loaded via side-effect imports.
 */
import { randomUUID } from "node:crypto";

globalThis.crypto ??= {};
globalThis.crypto.randomUUID ??= randomUUID;

// Load the severity module first (other modules depend on it)
await import("../lib/severity.js");
