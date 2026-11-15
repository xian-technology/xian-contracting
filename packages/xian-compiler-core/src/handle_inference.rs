//! Contract-handle inference, in work linear in the program.
//!
//! A contract handle is a value whose attributes lower to exported-function
//! calls of another contract: a static import, an `importlib.import_module`
//! call, a call of a *factory* (a function whose every return value is a
//! handle), a *parameter* to which every call site passes a handle, or a
//! *local* assigned a handle. These facts depend on each other across
//! functions; the inference finds their least fixpoint.
//!
//! Each fact is a node of one graph: a factory or a parameter holds when all
//! of its inputs (return values, call-site arguments) do, a local when any of
//! its inputs (assignments, its parameter) does. A worklist settles every
//! node once and follows every edge once.
//!
//! The earlier inference repeated whole-program passes (the factories under
//! the parameters known so far, then the parameters under those factories)
//! and refused a program that needed more than
//! `MAX_CONTRACT_HANDLE_INFERENCE_PASSES` of them. The worklist keeps that
//! rule exactly: it settles each fact at the pass that first found it (its
//! *level*) and refuses the same programs. Inside a pass the earlier
//! inference already closed factories and parameters, so a fact's level only
//! grows where a parameter feeds a factory: through a local of the
//! factory phase, whose parameter input weighs one level.
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::limits::{WorkBudget, WorkExceeded, MAX_CONTRACT_HANDLE_INFERENCE_PASSES};

/// When an expression is a contract handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleSource<'a> {
    Always,
    Never,
    /// When the function's local of this name holds a handle.
    Local(&'a str),
    /// When the module function of this name is a factory.
    Factory(&'a str),
}

/// A call-site argument of a module function's parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandleArgument<'a> {
    pub callee: &'a str,
    pub parameter: &'a str,
    pub source: HandleSource<'a>,
}

/// What the inference reads of one module function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FunctionHandleFacts<'a> {
    pub name: &'a str,
    pub parameters: Vec<&'a str>,
    pub returns: Vec<HandleSource<'a>>,
    pub assignments: Vec<(&'a str, HandleSource<'a>)>,
    pub arguments: Vec<HandleArgument<'a>>,
}

/// The inferred factories and handle parameters (per function).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ContractHandles {
    pub factories: HashSet<String>,
    pub parameters: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InferenceError {
    TooManyPasses,
    Work(WorkExceeded),
}

impl From<WorkExceeded> for InferenceError {
    fn from(error: WorkExceeded) -> Self {
        Self::Work(error)
    }
}

/// The least fixpoint of the handle facts of `functions`.
pub(crate) fn infer_contract_handles(
    functions: &[FunctionHandleFacts<'_>],
    work: &mut WorkBudget,
) -> Result<ContractHandles, InferenceError> {
    let mut graph = FactGraph::build(functions, work)?;
    graph.settle(work)?;
    Ok(graph.handles())
}

/// The phase of a whole-program pass a local is read in: the factory phase
/// sees the parameters of the pass before, the parameter phase its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Phase {
    Factories,
    Parameters,
}

impl Phase {
    /// The level a parameter input adds to a local of this phase.
    fn parameter_weight(self) -> u32 {
        match self {
            Self::Factories => 1,
            Self::Parameters => 0,
        }
    }
}

type NodeId = usize;

#[derive(Debug, Default)]
struct FactNode {
    /// An all-node (factory, parameter) holds when every input does; an
    /// any-node (local) when one does.
    all: bool,
    inputs: usize,
    unsettled: usize,
    impossible: bool,
    level: Option<u32>,
    /// Each dependent with the level it adds.
    dependents: Vec<(NodeId, u32)>,
}

#[derive(Default)]
struct FactGraph<'a> {
    nodes: Vec<FactNode>,
    factories: HashMap<&'a str, NodeId>,
    parameters: HashMap<(&'a str, &'a str), NodeId>,
    locals: HashMap<(Phase, usize, &'a str), NodeId>,
    /// Nodes that hold at level 1 whatever else does.
    seeds: Vec<NodeId>,
}

impl<'a> FactGraph<'a> {
    fn build(
        functions: &[FunctionHandleFacts<'a>],
        work: &mut WorkBudget,
    ) -> Result<Self, WorkExceeded> {
        let mut graph = Self::default();
        for function in functions {
            let node = graph.add_node(true);
            graph.factories.insert(function.name, node);
        }
        for argument in functions.iter().flat_map(|function| &function.arguments) {
            let key = (argument.callee, argument.parameter);
            if !graph.parameters.contains_key(&key) {
                let node = graph.add_node(true);
                graph.parameters.insert(key, node);
            }
        }
        for (index, function) in functions.iter().enumerate() {
            work.spend(graph.add_function(index, function))?;
        }
        graph.seed();
        Ok(graph)
    }

    /// Adds the inputs of `function` (the `index`th); returns how many.
    fn add_function(&mut self, index: usize, function: &FunctionHandleFacts<'a>) -> usize {
        let factory = self.factories[function.name];
        for source in &function.returns {
            self.add_input(factory, Phase::Factories, index, *source);
        }
        for argument in &function.arguments {
            let parameter = self.parameters[&(argument.callee, argument.parameter)];
            self.add_input(parameter, Phase::Parameters, index, argument.source);
        }
        let mut inputs = function.returns.len() + function.arguments.len();
        for phase in [Phase::Factories, Phase::Parameters] {
            for (name, source) in &function.assignments {
                let local = self.local(phase, index, name);
                self.add_input(local, phase, index, *source);
            }
            for name in &function.parameters {
                if let Some(&parameter) = self.parameters.get(&(function.name, *name)) {
                    let local = self.local(phase, index, name);
                    self.link(parameter, local, phase.parameter_weight());
                }
            }
            inputs += function.assignments.len() + function.parameters.len();
        }
        inputs
    }

    fn add_node(&mut self, all: bool) -> NodeId {
        self.nodes.push(FactNode {
            all,
            ..FactNode::default()
        });
        self.nodes.len() - 1
    }

    fn local(&mut self, phase: Phase, function: usize, name: &'a str) -> NodeId {
        if let Some(&node) = self.locals.get(&(phase, function, name)) {
            return node;
        }
        let node = self.add_node(false);
        self.locals.insert((phase, function, name), node);
        node
    }

    fn add_input(&mut self, node: NodeId, phase: Phase, function: usize, source: HandleSource<'a>) {
        let input = match source {
            HandleSource::Local(name) => Some(self.local(phase, function, name)),
            HandleSource::Factory(name) => self.factories.get(name).copied(),
            HandleSource::Always | HandleSource::Never => None,
        };
        match (input, source) {
            (Some(input), _) => self.link(input, node, 0),
            (None, HandleSource::Always) => self.add_held_input(node),
            (None, _) => self.add_failed_input(node),
        }
    }

    fn link(&mut self, input: NodeId, node: NodeId, weight: u32) {
        self.nodes[input].dependents.push((node, weight));
        let target = &mut self.nodes[node];
        target.inputs += 1;
        target.unsettled += 1;
    }

    fn add_held_input(&mut self, node: NodeId) {
        self.nodes[node].inputs += 1;
        if !self.nodes[node].all {
            self.seeds.push(node);
        }
    }

    fn add_failed_input(&mut self, node: NodeId) {
        let target = &mut self.nodes[node];
        target.inputs += 1;
        target.impossible |= target.all;
    }

    /// All-nodes whose inputs all hold from the start.
    fn seed(&mut self) {
        for (id, node) in self.nodes.iter().enumerate() {
            if node.all && node.unsettled == 0 && node.inputs > 0 && !node.impossible {
                self.seeds.push(id);
            }
        }
    }

    /// Settles every node that holds at its level, in level order.
    fn settle(&mut self, work: &mut WorkBudget) -> Result<(), InferenceError> {
        let mut level = 1;
        let mut current = std::mem::take(&mut self.seeds);
        let mut next = Vec::new();
        while !current.is_empty() {
            while let Some(id) = current.pop() {
                work.spend(1)?;
                if self.nodes[id].level.is_none() {
                    self.settle_node(id, level)?;
                    self.release_dependents(id, (&mut current, &mut next), work)?;
                }
            }
            std::mem::swap(&mut current, &mut next);
            level += 1;
        }
        Ok(())
    }

    /// Queues the dependents of settled `id` that now hold: at its level
    /// (`now`), or one level later for a weighted edge (`later`).
    fn release_dependents(
        &mut self,
        id: NodeId,
        (now, later): (&mut Vec<NodeId>, &mut Vec<NodeId>),
        work: &mut WorkBudget,
    ) -> Result<(), WorkExceeded> {
        let dependents = std::mem::take(&mut self.nodes[id].dependents);
        work.spend(dependents.len())?;
        for (dependent, weight) in dependents {
            if self.input_settled(dependent) {
                (if weight == 0 { &mut *now } else { &mut *later }).push(dependent);
            }
        }
        Ok(())
    }

    fn settle_node(&mut self, id: NodeId, level: u32) -> Result<(), InferenceError> {
        let node = &mut self.nodes[id];
        // A factory or parameter found at pass `level` needs pass
        // `level + 1` to confirm the fixpoint.
        if node.all && level as usize >= MAX_CONTRACT_HANDLE_INFERENCE_PASSES {
            return Err(InferenceError::TooManyPasses);
        }
        node.level = Some(level);
        Ok(())
    }

    /// Records one settled input of `id`; whether `id` now holds.
    fn input_settled(&mut self, id: NodeId) -> bool {
        let node = &mut self.nodes[id];
        if !node.all {
            return node.level.is_none();
        }
        node.unsettled -= 1;
        node.unsettled == 0 && !node.impossible
    }

    fn handles(&self) -> ContractHandles {
        let holds = |id: NodeId| self.nodes[id].level.is_some();
        let mut handles = ContractHandles {
            factories: self
                .factories
                .iter()
                .filter(|(_, id)| holds(**id))
                .map(|(name, _)| (*name).to_owned())
                .collect(),
            parameters: HashMap::new(),
        };
        for ((function, parameter), _) in self.parameters.iter().filter(|(_, id)| holds(**id)) {
            handles
                .parameters
                .entry((*function).to_owned())
                .or_default()
                .insert((*parameter).to_owned());
        }
        handles
    }
}

/// When an entry of a binding sweep can bind its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness<'a> {
    Now,
    /// Once this name is bound.
    After(&'a str),
    Never,
}

/// The entries that bind, in the order they bind, when sweeps over
/// `entries` in order repeat until one binds nothing: an entry binds its
/// target when the target is unbound (`bound` names start bound) and the
/// entry is ready. The earliest (sweep, index) wins, so the entries settle
/// in that order through a priority queue: n log n, not one sweep per link.
pub(crate) fn sweep_bindings(
    entries: &[(&str, Readiness<'_>)],
    bound: &HashSet<&str>,
    work: &mut WorkBudget,
) -> Result<Vec<usize>, WorkExceeded> {
    work.spend(entries.len())?;
    let mut sweep = Sweep::start(entries, bound);
    let mut order = Vec::new();
    while let Some(Reverse((pass, index))) = sweep.queue.pop() {
        work.spend(1)?;
        if sweep.bind(entries[index].0, pass, index) {
            order.push(index);
        }
    }
    Ok(order)
}

/// A sweep in progress: the entries queued by (sweep, index), the entries
/// waiting for a name, and the names bound so far.
struct Sweep<'e> {
    queue: BinaryHeap<Reverse<(usize, usize)>>,
    waiting: HashMap<&'e str, Vec<usize>>,
    bound: HashSet<&'e str>,
}

impl<'e> Sweep<'e> {
    fn start(entries: &[(&'e str, Readiness<'e>)], bound: &HashSet<&'e str>) -> Self {
        let mut sweep = Self {
            queue: BinaryHeap::new(),
            waiting: HashMap::new(),
            bound: bound.clone(),
        };
        for (index, (_, readiness)) in entries.iter().enumerate() {
            match readiness {
                Readiness::After(name) if !bound.contains(name) => {
                    sweep.waiting.entry(*name).or_default().push(index);
                }
                Readiness::Now | Readiness::After(_) => sweep.queue.push(Reverse((1, index))),
                Readiness::Never => {}
            }
        }
        sweep
    }

    /// Binds `target` by the entry at (`pass`, `index`) unless it is bound;
    /// whether it bound.
    fn bind(&mut self, target: &'e str, pass: usize, index: usize) -> bool {
        if !self.bound.insert(target) {
            return false;
        }
        for dependent in self.waiting.remove(target).unwrap_or_default() {
            // Later in this sweep, or in the next one.
            let at = if dependent > index { pass } else { pass + 1 };
            self.queue.push(Reverse((at, dependent)));
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        infer_contract_handles, sweep_bindings, FunctionHandleFacts, HandleArgument, HandleSource,
        InferenceError, Readiness,
    };
    use crate::limits::WorkBudget;
    use HandleSource::{Always, Factory, Local, Never};

    fn function<'a>(name: &'a str, parameters: &[&'a str]) -> FunctionHandleFacts<'a> {
        FunctionHandleFacts {
            name,
            parameters: parameters.to_vec(),
            ..FunctionHandleFacts::default()
        }
    }

    fn argument<'a>(
        callee: &'a str,
        parameter: &'a str,
        source: HandleSource<'a>,
    ) -> HandleArgument<'a> {
        HandleArgument {
            callee,
            parameter,
            source,
        }
    }

    fn infer(
        functions: &[FunctionHandleFacts<'_>],
    ) -> Result<super::ContractHandles, InferenceError> {
        infer_contract_handles(functions, &mut WorkBudget::default())
    }

    fn names(names: &[&str]) -> HashSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_factory_needs_every_return_and_at_least_one() {
        let mut all = function("all", &[]);
        all.returns = vec![Always, Factory("all")];
        let mut mixed = function("mixed", &[]);
        mixed.returns = vec![Always, Never];
        let empty = function("empty", &[]);
        let mut unknown = function("unknown", &[]);
        unknown.returns = vec![Factory("missing")];
        let handles = infer(&[all, mixed, empty, unknown]).expect("infers");
        // `all` returns itself: a cycle is no evidence on its own.
        assert_eq!(handles.factories, names(&[]));

        let mut direct = function("direct", &[]);
        direct.returns = vec![Always, Always];
        let mut wrapper = function("wrapper", &[]);
        wrapper.returns = vec![Factory("direct"), Local("h")];
        wrapper.assignments = vec![("h", Factory("direct")), ("h", Never)];
        let handles = infer(&[direct, wrapper]).expect("infers");
        assert_eq!(handles.factories, names(&["direct", "wrapper"]));
    }

    #[test]
    fn a_parameter_needs_every_call_site_to_pass_a_handle() {
        let mut caller = function("caller", &[]);
        caller.arguments = vec![
            argument("callee", "p", Always),
            argument("callee", "q", Always),
            argument("callee", "q", Local("unbound")),
        ];
        let mut forward = function("callee", &["p", "q"]);
        forward.returns = vec![Local("p")];
        forward.arguments = vec![argument("sink", "x", Local("p"))];
        let handles = infer(&[caller, forward, function("sink", &["x"])]).expect("infers");
        assert_eq!(handles.factories, names(&["callee"]));
        assert_eq!(handles.parameters.len(), 2);
        assert_eq!(handles.parameters["callee"], names(&["p"]));
        assert_eq!(handles.parameters["sink"], names(&["x"]));
    }

    /// `F{i}(p)` returns `p` and `U{i}` passes it `F{i-1}(...)`: factory i
    /// is found in pass i + 2, so `count` factories need pass count + 2.
    fn alternating<'a>(
        factories: &'a [String],
        users: &'a [String],
    ) -> Vec<FunctionHandleFacts<'a>> {
        let mut functions = Vec::new();
        for (index, (name, user)) in factories.iter().zip(users).enumerate() {
            let mut factory = function(name, &["p"]);
            factory.returns = vec![Local("p")];
            functions.push(factory);
            let source = if index == 0 {
                Always
            } else {
                Factory(&factories[index - 1])
            };
            let mut caller = function(user, &[]);
            caller.arguments = vec![argument(name, "p", source)];
            functions.push(caller);
        }
        functions
    }

    fn numbered(prefix: &str, count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{prefix}{index}")).collect()
    }

    #[test]
    fn the_pass_limit_counts_the_passes_of_the_earlier_inference() {
        let (factories, users) = (numbered("F", 511), numbered("U", 511));
        let handles = infer(&alternating(&factories[..510], &users[..510])).expect("510 fit");
        assert_eq!(handles.factories.len(), 510);
        assert_eq!(
            infer(&alternating(&factories, &users)),
            Err(InferenceError::TooManyPasses)
        );
    }

    #[test]
    fn inference_spends_work() {
        let mut factory = function("f", &[]);
        factory.returns = vec![Always];
        let mut work = WorkBudget::with_limit(1);
        assert!(matches!(
            infer_contract_handles(&[factory], &mut work),
            Err(InferenceError::Work(_))
        ));
    }

    #[test]
    fn sweeps_bind_in_sweep_order() {
        let entries = [
            ("x", Readiness::After("y")),
            ("y", Readiness::Now),
            ("x", Readiness::Now),
            ("z", Readiness::After("w")),
            ("w", Readiness::After("x")),
            ("v", Readiness::Never),
            ("u", Readiness::After("p")),
        ];
        let bound = HashSet::from(["p"]);
        let order = sweep_bindings(&entries, &bound, &mut WorkBudget::default()).expect("fits");
        // Sweep 1: y (1), x (2), w (4, x is bound by then), u (6).
        // Sweep 2: z (3).
        assert_eq!(order, [1, 2, 4, 6, 3]);
        assert!(sweep_bindings(&entries, &bound, &mut WorkBudget::with_limit(8)).is_err());
    }
}
