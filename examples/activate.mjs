// Activate a licence (key, sign-in or trial) and check it, the way an app does on start-up.
//   node examples/activate.mjs your-shop <public-key-hex> [LICENCE-KEY]
//   node examples/activate.mjs your-shop <public-key-hex> --signin <product-id>
//   node examples/activate.mjs your-shop <public-key-hex> --trial <product-id>
import { homedir } from "node:os";
import { join } from "node:path";
import { Client } from "../dist/index.js";

const [tenant, publicKeyHex, arg, productId] = process.argv.slice(2);
const client = new Client({ tenant, publicKeyHex, productId, appVersion: "1.0.0", buildDate: new Date("2026-11-01T00:00:00Z"),
  cachePath: join(homedir(), ".example-app", "licence.json") });
if (arg === "--signin") {
  const s = await client.startSignIn();
  console.log(`Open ${s.verificationUrl} and approve code ${s.userCode}`);
  await client.waitForSignIn(s);
} else if (arg === "--trial") {
  await client.startTrial();
} else if (arg) {
  await client.activate(arg);
}
const state = await client.check();
if (!state.canRun) { console.error("licence not valid for this build", state.error); process.exit(1); }
console.log(`licensed (${state.token.payload.status}, ${state.token.payload.license_model}, online=${state.online})`);
if (state.token.payload.license_model === "floating") await client.release(); // free the seat on exit
