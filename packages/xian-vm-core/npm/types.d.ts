// The JSON shapes `VmChain` takes and returns (see README.md). Every contract
// value in a result is wire JSON text: a string holding the value's wire
// encoding, so no JS number ever carries a decimal or a large int.

/** Wire JSON text of one value, e.g. '{"__fixed__":"1.5"}'. */
export type WireText = string;

/** A wire value inline in a request (built from strings, never JS floats). */
export type WireValue =
  | null
  | boolean
  | number // safe integers only
  | string
  | WireValue[]
  | { [key: string]: WireValue };

/** The block a transaction runs in. */
export interface Environment {
  /** [year, month, day, hour?, minute?, second?, microsecond?] */
  now?: { __time__: number[] };
  block_num?: number | { __big_int__: string };
  block_hash?: string;
  chain_id?: string;
  /** The random seed input; without it random.* fails. */
  input_hash?: string;
}

export interface CreateOptions {
  environment?: Environment;
}

interface RunOptions {
  environment?: Environment;
  /** Default true (the chain always meters). */
  metering?: boolean;
  /** Default 0: the VM ceiling (1,000,000 chi). Metered calls only. */
  chi_budget?: number;
  /** Default false: fees need currency and chi_cost deployed. */
  charge_fees?: boolean;
  /** Default true; false is a dry run. */
  commit?: boolean;
}

export interface CallRequest extends RunOptions {
  sender: string;
  contract: string;
  function: string;
  kwargs?: Record<string, WireValue>;
  /** Default 0 (no size charge). */
  transaction_size_bytes?: number;
}

export interface DeployRequest extends RunOptions {
  sender: string;
  name: string;
  source: string;
  owner?: string;
  constructor_args?: Record<string, WireValue>;
}

export interface TxEvent {
  contract: string;
  event: string;
  signer: WireText;
  caller: WireText;
  data_indexed: WireText;
  data: WireText;
}

export interface TxOutcome {
  status: number;
  result: WireText;
  error: string | null;
  exception: { name: string; args: WireText[] } | null;
  chi_used: number;
  writes: Array<[string, WireText | null]>;
  events: TxEvent[];
  contract_costs: Record<string, number>;
  unprepared: boolean;
}

export interface ArgumentInfo {
  name: string;
  type: string | null;
  kind: string;
  optional: boolean;
}

export interface MethodInfo {
  name: string;
  arguments: ArgumentInfo[];
  returns: string | null;
  docstring: string | null;
}

export interface ContractInfo {
  name: string;
  source: string | null;
  vm_ir_json: string;
  owner: WireText | null;
  developer: WireText | null;
  deployer: WireText | null;
  initiator: WireText | null;
  submitted: WireText | null;
  methods: MethodInfo[];
  construct: { name: string; arguments: ArgumentInfo[] } | null;
}

export interface StateSnapshot {
  format: "xian-vm-state/1";
  entries: Array<[string, WireText]>;
}

export interface RuntimeInfo {
  version: string;
  vm_profile: string;
  execution_revision: string;
  gas_schedule: string;
  zk: boolean;
}
