import { afterAll, beforeAll, describe, expect, test } from "vitest";
import type { HelloOk } from "../../packages/gateway-protocol/src/index.js";
import { approveNodePairing, listNodePairing } from "../infra/node-pairing.js";
import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../utils/message-channel.js";
import { pairDeviceIdentity } from "./device-authz.test-helpers.js";
import {
  createNodePairingTestState,
  describeWithGatewayServer,
} from "./server.node-pairing.test-support.js";
import { connectGatewayClient } from "./test-helpers.e2e.js";
import { installGatewayTestHooks } from "./test-helpers.js";

installGatewayTestHooks({ scope: "suite" });

const { cleanup: cleanupNodePairingTestState, setup: setupNodePairingTestState } =
  createNodePairingTestState("openclaw-node-pair-plugin-surface-");

async function connectCanvasNode(params: {
  port: number;
  deviceIdentity: Awaited<ReturnType<typeof pairDeviceIdentity>>["identity"];
  onHelloOk: (hello: HelloOk) => void;
}) {
  return await connectGatewayClient({
    url: `ws://127.0.0.1:${params.port}`,
    token: "secret",
    role: "node",
    clientName: GATEWAY_CLIENT_NAMES.NODE_HOST,
    clientDisplayName: "node-plugin-surface-approval",
    clientVersion: "1.0.0",
    platform: "macos",
    deviceFamily: "Mac",
    mode: GATEWAY_CLIENT_MODES.NODE,
    scopes: [],
    caps: ["canvas"],
    commands: [],
    deviceIdentity: params.deviceIdentity,
    onHelloOk: params.onHelloOk,
    timeoutMessage: "timeout waiting for paired node to connect",
  });
}

describe("gateway node pairing plugin surface authorization", () => {
  beforeAll(async () => {
    await setupNodePairingTestState();
  });

  afterAll(async () => {
    await cleanupNodePairingTestState();
  });

  describeWithGatewayServer("paired node reconnects", (getStarted) => {
    test("withholds plugin surface URLs until the node capability is approved", async () => {
      // The shared Gateway harness disables Canvas startup; expose its descriptor
      // so this handshake test exercises production capability issuance.
      const previousSkipCanvasHost = process.env.OPENCLAW_SKIP_CANVAS_HOST;
      delete process.env.OPENCLAW_SKIP_CANVAS_HOST;
      try {
        const pairedNode = await pairDeviceIdentity({
          name: "node-plugin-surface-approval",
          role: "node",
          scopes: [],
          clientId: GATEWAY_CLIENT_NAMES.NODE_HOST,
          clientMode: GATEWAY_CLIENT_MODES.NODE,
        });
        let pendingHello: HelloOk | undefined;
        const pendingClient = await connectCanvasNode({
          port: getStarted().port,
          deviceIdentity: pairedNode.identity,
          onHelloOk: (hello) => {
            pendingHello = hello;
          },
        });
        await pendingClient.stopAndWait();

        expect(pendingHello?.pluginSurfaceUrls).toBeUndefined();
        const pending = (await listNodePairing()).pending.find(
          (entry) => entry.nodeId === pairedNode.identity.deviceId,
        );
        expect(pending?.caps).toEqual(["canvas"]);
        const approval = await approveNodePairing(pending?.requestId ?? "", {
          callerScopes: ["operator.pairing"],
        });
        expect(approval).toMatchObject({ requestId: pending?.requestId });

        let approvedHello: HelloOk | undefined;
        const approvedClient = await connectCanvasNode({
          port: getStarted().port,
          deviceIdentity: pairedNode.identity,
          onHelloOk: (hello) => {
            approvedHello = hello;
          },
        });
        try {
          expect(approvedHello?.pluginSurfaceUrls?.canvas).toMatch(
            /^http:\/\/127\.0\.0\.1:\d+\/__openclaw__\/cap\/[^/]+$/,
          );
        } finally {
          await approvedClient.stopAndWait();
        }
      } finally {
        if (previousSkipCanvasHost === undefined) {
          delete process.env.OPENCLAW_SKIP_CANVAS_HOST;
        } else {
          process.env.OPENCLAW_SKIP_CANVAS_HOST = previousSkipCanvasHost;
        }
      }
    });
  });
});
