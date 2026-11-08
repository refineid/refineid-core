// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! The lifecycle machines of the RAPP state model: every state and event
//! pair has exactly one answer, the requester shows no custodian state, the
//! lifecycle constants agree with the stamped ones, and every scenario of
//! the lifecycle corpus walks the model as it says.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const MODEL: &str = include_str!("../../../doc/protocols/rapp-state-machine-v26.11.8.yaml");
const CORPUS: &str = include_str!("../../../doc/protocols/vectors/rapp-lifecycle-v26.11.8.json");

/// The three lifecycle machines, each with its one role.
const LIFECYCLE_MACHINES: &[(&str, &str)] = &[
    ("requester_remote_use", "requester"),
    ("requester_view_of_custodian", "requester"),
    ("custodian_service", "custodian"),
];

#[derive(Deserialize)]
struct Model {
    document_version: String,
    constants: Constants,
    guards: BTreeMap<String, String>,
    actions: BTreeMap<String, String>,
    pairing: Machine,
    session: Machine,
    requester_remote_use: Machine,
    requester_view_of_custodian: Machine,
    custodian_service: Machine,
}

#[derive(Deserialize)]
struct Constants {
    session_silence_limit_ms: u64,
    identity_offer_grace_ms: u64,
    redial_window_ms: u64,
}

#[derive(Deserialize)]
struct Machine {
    role: Option<String>,
    initial: String,
    states: Vec<String>,
    #[serde(default)]
    events: Vec<String>,
    transitions: Vec<Rule>,
    #[serde(default)]
    ignored: Vec<Entry>,
    #[serde(default)]
    cannot_happen: Vec<Entry>,
    #[serde(default)]
    presentation: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Rule {
    from: OneOrMany,
    event: OneOrMany,
    role: Option<String>,
    guard: Option<OneOrMany>,
    to: String,
    actions: Vec<String>,
}

#[derive(Deserialize)]
struct Entry {
    from: OneOrMany,
    event: OneOrMany,
    guard: Option<OneOrMany>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn values(&self) -> Vec<&str> {
        match self {
            Self::One(value) => vec![value.as_str()],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    machine: String,
    role: String,
    start: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    event: String,
    #[serde(default)]
    guards: Vec<String>,
    outcome: String,
    state: Option<String>,
    actions: Option<Vec<String>>,
}

fn model() -> Model {
    serde_saphyr::from_str(MODEL).expect("normative RAPP state model must parse")
}

impl Model {
    fn machine(&self, name: &str) -> &Machine {
        match name {
            "pairing" => &self.pairing,
            "session" => &self.session,
            "requester_remote_use" => &self.requester_remote_use,
            "requester_view_of_custodian" => &self.requester_view_of_custodian,
            "custodian_service" => &self.custodian_service,
            other => panic!("unknown machine {other}"),
        }
    }
}

/// What one machine says for one state and event.
#[derive(Default)]
struct Cell {
    unguarded_rules: usize,
    guarded_rules: usize,
    guarded_cannot: usize,
    ignored: usize,
    cannot: usize,
}

#[test]
fn every_lifecycle_cell_has_exactly_one_answer() {
    let model = model();
    for &(name, role) in LIFECYCLE_MACHINES {
        let machine = model.machine(name);
        assert_eq!(machine.role.as_deref(), Some(role), "{name} names its role");
        let states = machine
            .states
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let events = machine
            .events
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert!(states.contains(machine.initial.as_str()), "{name} initial");
        let mut cells = BTreeMap::<(&str, &str), Cell>::new();
        for rule in &machine.transitions {
            assert!(
                states.contains(rule.to.as_str()),
                "{name}: unknown target {}",
                rule.to
            );
            for action in &rule.actions {
                assert!(
                    model.actions.contains_key(action),
                    "{name}: unregistered action {action}"
                );
            }
            if let Some(guard) = &rule.guard {
                for guard in guard.values() {
                    assert!(
                        model.guards.contains_key(guard),
                        "{name}: unregistered guard {guard}"
                    );
                }
            }
            for from in rule.from.values() {
                for event in rule.event.values() {
                    let cell = cells.entry((from, event)).or_default();
                    if rule.guard.is_some() {
                        cell.guarded_rules += 1;
                    } else {
                        cell.unguarded_rules += 1;
                    }
                }
            }
        }
        for (entries, ignored) in [(&machine.ignored, true), (&machine.cannot_happen, false)] {
            for entry in entries {
                assert!(
                    !entry.reason.trim().is_empty(),
                    "{name}: an entry without a reason"
                );
                for from in entry.from.values() {
                    for event in entry.event.values() {
                        let cell = cells.entry((from, event)).or_default();
                        match (ignored, entry.guard.is_some()) {
                            (true, _) => cell.ignored += 1,
                            (false, true) => cell.guarded_cannot += 1,
                            (false, false) => cell.cannot += 1,
                        }
                    }
                }
            }
        }
        for &(from, event) in cells.keys() {
            assert!(states.contains(from), "{name}: unknown state {from}");
            assert!(events.contains(event), "{name}: unknown event {event}");
        }
        for &state in &states {
            for &event in &events {
                let cell = cells.get(&(state, event));
                assert!(
                    cell.is_some_and(Cell::is_one_answer),
                    "{name}: {state} / {event}"
                );
            }
        }
    }
}

impl Cell {
    /// One unguarded rule, or rules and guarded impossibilities told apart
    /// by guards, or one ignored entry, or one impossibility.
    fn is_one_answer(&self) -> bool {
        let entries = self.ignored + self.cannot;
        let rules = self.unguarded_rules + self.guarded_rules + self.guarded_cannot;
        if entries > 0 {
            return entries == 1 && rules == 0;
        }
        if self.unguarded_rules > 0 {
            return self.unguarded_rules == 1 && self.guarded_rules + self.guarded_cannot == 0;
        }
        self.guarded_rules > 0
    }
}

#[test]
fn the_requester_shows_no_state_of_the_custodian() {
    let model = model();
    let view = &model.requester_view_of_custodian;
    for state in &view.states {
        let shown = view
            .presentation
            .get(state)
            .unwrap_or_else(|| panic!("{state} has a presentation"));
        let remote_card = state == "connected";
        assert_eq!(shown.starts_with("the remote card"), remote_card, "{state}");
        if !remote_card && state != "ended" {
            assert!(shown.starts_with("no remote card"), "{state}");
        }
    }
    let shown = view
        .transitions
        .iter()
        .flat_map(|rule| rule.actions.iter())
        .filter(|action| action.starts_with("show_"))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(shown, BTreeSet::from(["show_peer_forgot"]));
}

#[test]
fn a_withdrawn_custodian_is_dialed_only_after_it_announces_itself() {
    let model = model();
    let view = &model.requester_view_of_custodian;
    for rule in &view.transitions {
        if !rule.from.values().contains(&"withdrawn") {
            continue;
        }
        if rule
            .actions
            .iter()
            .any(|action| action == "open_session_dial")
        {
            for event in rule.event.values() {
                assert!(
                    matches!(event, "record_appeared" | "advertisement_appeared"),
                    "withdrawn dials on {event}"
                );
            }
        }
        assert!(
            !rule
                .actions
                .iter()
                .any(|action| matches!(action.as_str(), "schedule_redial" | "start_offer_grace")),
            "withdrawn redials or offers"
        );
    }
}

#[test]
fn a_custodian_switch_never_touches_a_pairing() {
    let model = model();
    let switch_rules = model
        .custodian_service
        .transitions
        .iter()
        .filter(|rule| {
            rule.event
                .values()
                .iter()
                .any(|event| matches!(*event, "holder_turns_on" | "holder_turns_off"))
        })
        .collect::<Vec<_>>();
    assert!(!switch_rules.is_empty(), "the model names the switch");
    for rule in switch_rules {
        for action in &rule.actions {
            assert!(
                !action.contains("pair") || action == "cancel_offer",
                "custodian_service changes a pairing: {action}"
            );
            assert!(
                !action.contains("revok") && !action.contains("forget"),
                "{action}"
            );
        }
    }
}

#[test]
fn lifecycle_constants_agree_with_the_stamped_ones() {
    let constants = model().constants;
    assert_eq!(
        constants.redial_window_ms,
        constants.identity_offer_grace_ms
    );
    assert!(constants.session_silence_limit_ms < constants.redial_window_ms);
}

#[test]
fn every_lifecycle_scenario_walks_the_model() {
    let model = model();
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("lifecycle corpus must parse");
    assert_eq!(corpus.format, "fi.refineid.rapp.lifecycle-vectors");
    assert_eq!(corpus.protocol_document_version, model.document_version);
    assert!(!corpus.scenarios.is_empty());
    for scenario in &corpus.scenarios {
        let machine = model.machine(&scenario.machine);
        let mut state = scenario.start.clone();
        for step in &scenario.steps {
            let label = format!("{} / {} / {}", scenario.name, state, step.event);
            let given = step
                .guards
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let matching = machine
                .transitions
                .iter()
                .filter(|rule| applies(rule, &state, &step.event, &scenario.role, &given))
                .collect::<Vec<_>>();
            let entry_says = |entries: &[Entry]| {
                entries.iter().any(|entry| {
                    entry.from.values().contains(&state.as_str())
                        && entry.event.values().contains(&step.event.as_str())
                        && entry
                            .guard
                            .as_ref()
                            .is_none_or(|guard| guard.values().iter().all(|g| given.contains(g)))
                })
            };
            match step.outcome.as_str() {
                "transition" => {
                    assert_eq!(matching.len(), 1, "{label}: one rule applies");
                    let rule = matching.first().expect("one rule");
                    assert_eq!(Some(&rule.to), step.state.as_ref(), "{label}");
                    assert_eq!(Some(&rule.actions), step.actions.as_ref(), "{label}");
                    state.clone_from(&rule.to);
                }
                "ignored" => {
                    assert!(
                        matching.is_empty() && entry_says(&machine.ignored),
                        "{label}"
                    );
                }
                "cannot_happen" => {
                    let impossible = entry_says(&machine.cannot_happen)
                        || (machine.cannot_happen.is_empty() && machine.ignored.is_empty());
                    assert!(matching.is_empty() && impossible, "{label}");
                }
                other => panic!("{label}: unknown outcome {other}"),
            }
        }
    }
}

fn applies(rule: &Rule, state: &str, event: &str, role: &str, given: &BTreeSet<&str>) -> bool {
    rule.from.values().contains(&state)
        && rule.event.values().contains(&event)
        && rule
            .role
            .as_deref()
            .is_none_or(|rule_role| rule_role == "both" || rule_role == role)
        && rule
            .guard
            .as_ref()
            .is_none_or(|guard| guard.values().iter().all(|g| given.contains(g)))
}
