// Covers the graded identifier authentication gate: how entry-side and per-message claims
// combine, and that channels which say nothing keep their current admissions.
import { describe, expect, it } from "vitest";
import { decideChannelIngress } from "./decision.js";
import {
  meetsIdentifierAuthentication,
  minimumIdentifierAuthenticationFrom,
  weakestIdentifierAuthentication,
  type IdentifierAuthentication,
} from "./identifier-authentication.js";
import type {
  ChannelIngressPolicyInput,
  ChannelIngressStateInput,
  InternalChannelIngressAdapter,
  InternalChannelIngressSubject,
} from "./index.js";
import { resolveChannelIngressState } from "./state.js";

/**
 * Two kinds so the per-kind pairing is actually exercised: an address that a message can
 * authenticate, and a display name that no message can. Mail is the motivating shape.
 */
const adapter: InternalChannelIngressAdapter = {
  normalizeEntries({ entries }) {
    return {
      matchable: entries.map((entry, index) => {
        const isName = entry.startsWith("name:");
        return {
          opaqueEntryId: `entry-${index + 1}`,
          kind: isName ? ("username" as const) : ("email" as const),
          value: entry,
          ...(isName ? { authentication: "mutable" as const } : {}),
        };
      }),
      invalid: [],
      disabled: [],
    };
  },
  matchSubject({ subject, entries }) {
    const values = new Set(subject.identifiers.map((identifier) => identifier.value));
    const matchedEntryIds = entries
      .filter((entry) => entry.value === "*" || values.has(entry.value))
      .map((entry) => entry.opaqueEntryId);
    return { matched: matchedEntryIds.length > 0, matchedEntryIds };
  },
};

function subject(params: {
  address: string;
  addressAuthentication?: IdentifierAuthentication;
  displayName?: string;
}): InternalChannelIngressSubject {
  return {
    identifiers: [
      {
        opaqueId: "address",
        kind: "email",
        value: params.address,
        ...(params.addressAuthentication
          ? { authentication: params.addressAuthentication }
          : {}),
      },
      ...(params.displayName
        ? [{ opaqueId: "displayName", kind: "username" as const, value: params.displayName }]
        : []),
    ],
  };
}

function input(overrides: Partial<ChannelIngressStateInput> = {}): ChannelIngressStateInput {
  return {
    channelId: "test",
    accountId: "default",
    subject: subject({ address: "omar@shahine.com" }),
    conversation: { kind: "direct", id: "dm-1" },
    adapter,
    event: { kind: "message", authMode: "inbound", mayPair: false },
    allowlists: { dm: ["omar@shahine.com"] },
    ...overrides,
  };
}

const allowlistPolicy: ChannelIngressPolicyInput = {
  dmPolicy: "allowlist",
  groupPolicy: "allowlist",
};

async function admit(
  stateInput: ChannelIngressStateInput,
  policy: ChannelIngressPolicyInput = allowlistPolicy,
) {
  return decideChannelIngress(await resolveChannelIngressState(stateInput), policy);
}

describe("identifier authentication scale", () => {
  it("orders verified above asserted above unverified above mutable", () => {
    expect(meetsIdentifierAuthentication("verified", "asserted")).toBe(true);
    expect(meetsIdentifierAuthentication("asserted", "asserted")).toBe(true);
    expect(meetsIdentifierAuthentication("unverified", "asserted")).toBe(false);
    expect(meetsIdentifierAuthentication("mutable", "unverified")).toBe(false);
    // The two weak levels are distinct, not aliases.
    expect(meetsIdentifierAuthentication("unverified", "mutable")).toBe(true);
  });

  it("takes the weaker side, which is how entry and subject combine", () => {
    expect(weakestIdentifierAuthentication("verified", "unverified")).toBe("unverified");
    expect(weakestIdentifierAuthentication("asserted", "verified")).toBe("asserted");
  });

  it.each([
    { policy: {}, expected: "asserted" },
    { policy: { mutableIdentifierMatching: "enabled" as const }, expected: "mutable" },
    { policy: { mutableIdentifierMatching: "disabled" as const }, expected: "asserted" },
    // The graded knob is the newer, narrower statement, so it outranks the boolean.
    {
      policy: {
        minIdentifierAuthentication: "verified" as const,
        mutableIdentifierMatching: "enabled" as const,
      },
      expected: "verified",
    },
  ])("resolves minimum $expected", ({ policy, expected }) => {
    expect(minimumIdentifierAuthenticationFrom(policy)).toBe(expected);
  });
});

describe("channels that make no per-message claim", () => {
  it("admits an undescribed entry at the shipped default", async () => {
    // The whole compatibility bet: silence means `asserted`, and `asserted` clears the
    // default minimum. Every channel on main is in exactly this state.
    expect(await admit(input())).toMatchObject({ admission: "dispatch", decision: "allow" });
  });

  it("still rejects a mutable entry, with the long-standing reason code", async () => {
    const stateInput = input({
      subject: subject({ address: "someone@example.com", displayName: "name:Omar" }),
      allowlists: { dm: ["name:Omar"] },
    });
    const state = await resolveChannelIngressState(stateInput);

    expect(decideChannelIngress(state, allowlistPolicy)).toMatchObject({ admission: "drop" });
    // Existing diagnostics must not shift under the new gate.
    expect(state.allowlists.dm.normalizedEntries).toHaveLength(1);
    const decision = decideChannelIngress(state, allowlistPolicy);
    const gate = decision.graph.gates.find((candidate) => candidate.kind === "dmSender");
    expect(gate?.allowlist?.disabledEntryCount).toBe(1);
  });

  it("admits that same mutable entry when the policy accepts aliases", async () => {
    const stateInput = input({
      subject: subject({ address: "someone@example.com", displayName: "name:Omar" }),
      allowlists: { dm: ["name:Omar"] },
    });
    expect(
      await admit(stateInput, { ...allowlistPolicy, mutableIdentifierMatching: "enabled" }),
    ).toMatchObject({ admission: "dispatch" });
  });
});

describe("per-message subject claims", () => {
  it("rejects a matching entry when the message authenticated nothing", async () => {
    // The mail case. The address is allowlisted and matched; the message did not prove the
    // sender holds it, so the entry cannot authorize.
    const state = await resolveChannelIngressState(
      input({
        subject: subject({ address: "omar@shahine.com", addressAuthentication: "unverified" }),
      }),
    );

    expect(state.subjectAuthentication).toEqual({ email: "unverified" });
    expect(decideChannelIngress(state, allowlistPolicy)).toMatchObject({ admission: "drop" });
    expect(state.allowlists.dm.match.matched).toBe(true);
  });

  it("names the new reason on the disabled entry, not the alias reason", async () => {
    const state = await resolveChannelIngressState(
      input({
        subject: subject({ address: "omar@shahine.com", addressAuthentication: "unverified" }),
      }),
    );
    const decision = decideChannelIngress(state, allowlistPolicy);
    const gate = decision.graph.gates.find((candidate) => candidate.kind === "dmSender");

    expect(gate?.allowlist?.disabledEntryCount).toBe(1);
    expect(gate?.allowlist?.matched).toBe(false);
  });

  it("admits the same sender when the message authenticated the address", async () => {
    expect(
      await admit(
        input({
          subject: subject({ address: "omar@shahine.com", addressAuthentication: "verified" }),
        }),
      ),
    ).toMatchObject({ admission: "dispatch", decision: "allow" });
  });

  it("weakens only its own kind", async () => {
    // An unauthenticated display name must not disqualify an address entry.
    const state = await resolveChannelIngressState(
      input({
        subject: {
          identifiers: [
            { opaqueId: "address", kind: "email", value: "omar@shahine.com" },
            {
              opaqueId: "displayName",
              kind: "username",
              value: "name:Omar",
              authentication: "mutable",
            },
          ],
        },
      }),
    );

    expect(state.subjectAuthentication).toEqual({ username: "mutable" });
    expect(decideChannelIngress(state, allowlistPolicy)).toMatchObject({ admission: "dispatch" });
  });

  it("takes the weaker claim when one kind is described twice", async () => {
    const state = await resolveChannelIngressState(
      input({
        subject: {
          identifiers: [
            {
              opaqueId: "a",
              kind: "email",
              value: "omar@shahine.com",
              authentication: "verified",
            },
            {
              opaqueId: "b",
              kind: "email",
              value: "omar+tag@shahine.com",
              authentication: "unverified",
            },
          ],
        },
      }),
    );

    expect(state.subjectAuthentication).toEqual({ email: "unverified" });
  });

  it("applies to a wildcard entry through the identifier it stands in for", async () => {
    // A wildcard waives the allowlist, not authentication: an open channel still has to
    // know who is speaking as well as the minimum requires.
    const stateInput = input({
      subject: subject({ address: "stranger@example.com", addressAuthentication: "unverified" }),
      allowlists: { dm: ["*"] },
    });
    const wildcardAdapter: InternalChannelIngressAdapter = {
      ...adapter,
      normalizeEntries({ entries }) {
        return {
          matchable: entries.map((entry, index) => ({
            opaqueEntryId: `entry-${index + 1}`,
            kind: "email" as const,
            value: entry,
          })),
          invalid: [],
          disabled: [],
        };
      },
    };

    expect(await admit({ ...stateInput, adapter: wildcardAdapter })).toMatchObject({
      admission: "drop",
    });
  });
});

describe("raising the minimum", () => {
  it("rejects an entry no message backed, however well the sender matched", async () => {
    expect(
      await admit(input(), { ...allowlistPolicy, minIdentifierAuthentication: "verified" }),
    ).toMatchObject({ admission: "drop" });
  });

  it("admits it once a message proves the address", async () => {
    expect(
      await admit(
        input({
          subject: subject({ address: "omar@shahine.com", addressAuthentication: "verified" }),
        }),
        { ...allowlistPolicy, minIdentifierAuthentication: "verified" },
      ),
    ).toMatchObject({ admission: "dispatch" });
  });

  it("gates control commands on the same claim", async () => {
    // A weak message must not authorize a command either; the command gate reads the same
    // allowlists and has to apply the same bar.
    const decision = await admit(
      input({
        subject: subject({ address: "omar@shahine.com", addressAuthentication: "unverified" }),
        allowlists: { dm: ["omar@shahine.com"], commandOwner: ["omar@shahine.com"] },
      }),
      {
        ...allowlistPolicy,
        command: { allowTextCommands: true, hasControlCommand: true },
      },
    );

    expect(decision).toMatchObject({ admission: "drop" });
    const commandGate = decision.graph.gates.find((gate) => gate.kind === "command");
    expect(commandGate?.allowed).toBe(false);
  });
});

describe("redaction", () => {
  it("keeps raw sender values out of state and decisions", async () => {
    const raw = "very-distinctive-sender@example.test";
    const stateInput = input({
      subject: subject({ address: raw, addressAuthentication: "unverified" }),
      allowlists: { dm: [raw] },
    });
    const state = await resolveChannelIngressState(stateInput);
    const decision = decideChannelIngress(state, allowlistPolicy);

    expect(JSON.stringify(state)).not.toContain(raw);
    expect(JSON.stringify(decision)).not.toContain(raw);
  });
});
