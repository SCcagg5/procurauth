//! The options route (5.6 to 5.9) with the PEP and the test PDP. The tests cover the
//! questions for each child, the pages, the bound on the questions and the failures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use common::*;
use fake_pdp::{Options, Server};
use procurauth_core::path::NodePath;
use procurauth_pep::config::PepConfig;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use procurauth_pep::options::{Candidate, CandidatePage, OptionsQuery, OptionsSource};
use procurauth_pep::{Pep, Refusal};
use serde_json::{Value, json};

/// The data of the service: hosts, and the databases of each host.
struct Data(BTreeMap<String, Vec<String>>);

impl Data {
    fn new() -> Self {
        let mut m = BTreeMap::new();
        m.insert("".to_owned(), vec!["prod".to_owned(), "staging".to_owned()]);
        m.insert(
            "host:prod".to_owned(),
            ["a", "b", "test1", "c", "d", "test2", "a/b", "e"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        );
        Self(m)
    }
}

impl OptionsSource for Data {
    fn children(
        &self,
        parent: &NodePath,
        _type: &str,
        q: Option<&str>,
        after: Option<&str>,
        max: usize,
    ) -> CandidatePage {
        let key = parent
            .to_string()
            .trim_start_matches("service:datastore")
            .trim_start_matches('/')
            .to_owned();
        let all = self.0.get(&key).cloned().unwrap_or_default();
        let start = after.map_or(0, |a| a.parse::<usize>().unwrap());
        let matching: Vec<(usize, &String)> = all
            .iter()
            .enumerate()
            .skip(start)
            .filter(|(_, id)| q.is_none_or(|q| id.contains(q)))
            .collect();
        let candidates: Vec<Candidate> = matching
            .iter()
            .take(max)
            .map(|(i, id)| Candidate {
                id: (*id).clone(),
                label: (*id).clone(),
                has_children: key.is_empty(),
                cursor: (i + 1).to_string(),
            })
            .collect();
        CandidatePage {
            more: matching.len() > candidates.len(),
            candidates,
        }
    }
}

struct Rig {
    pep: Pep,
    who: procurauth_pep::Identity,
    server: fake_pdp::RunningServer,
}

fn rig(tweak: impl FnOnce(&mut PepConfig)) -> Rig {
    let data = datastore_data();
    let server = Server::from_value(&data, Options::default())
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap();
    let edge = Edge::new();
    let mut cfg = config(&server.url(), &edge);
    tweak(&mut cfg);
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&cfg.pdp)));
    let clock = procurauth_pep::clock::ManualClock::at_seconds(NOW);
    let pep = Pep::with_clock(cfg, document_of(&data), transport, Arc::new(clock)).unwrap();
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    Rig { pep, who, server }
}

fn query(text: &str, pep: &Pep) -> OptionsQuery {
    OptionsQuery::parse(text, pep.document()).unwrap()
}

fn ids(answer: &procurauth_core::options::OptionsAnswer) -> Vec<&str> {
    answer.items.iter().map(|i| i.id.as_str()).collect()
}

#[test]
fn p_5_6_the_first_level_has_only_the_children_that_the_subject_can_see() {
    let r = rig(|_| {});
    let answer = r
        .pep
        .options(&r.who, &query("type=host", &r.pep), None, &Data::new())
        .unwrap();
    // Alice has grants below `host:prod` and none below `host:staging`.
    assert_eq!(ids(&answer), ["prod"]);
    assert!(answer.items[0].has_children);
    assert_eq!(answer.next, None);
    // The answer is a good answer of the options route (5.8).
    let (parsed, report) = procurauth_core::options::analyze_value(&answer.to_value());
    assert!(parsed.is_some());
    assert!(report.findings().is_empty());
}

#[test]
fn p_5_8_the_example_of_the_text_lists_test1_and_test2_with_a_search() {
    let r = rig(|_| {});
    let q = query("parent=host%3Aprod&type=database&q=test&limit=2", &r.pep);
    let answer = r.pep.options(&r.who, &q, None, &Data::new()).unwrap();
    assert_eq!(ids(&answer), ["test1", "test2"]);
    assert_eq!(answer.next, None);
}

#[test]
fn p_5_7_the_limit_bounds_the_items_and_next_gives_the_page_after() {
    let r = rig(|_| {});
    let q = query("parent=host%3Aprod&type=database&limit=1", &r.pep);
    let first = r.pep.options(&r.who, &q, None, &Data::new()).unwrap();
    assert_eq!(ids(&first), ["test1"]);
    let next = first.next.clone().unwrap();
    let q = query(
        &format!("parent=host%3Aprod&type=database&limit=1&after={next}"),
        &r.pep,
    );
    let second = r.pep.options(&r.who, &q, None, &Data::new()).unwrap();
    assert_eq!(ids(&second), ["test2"]);
    // The last child is the id `a/b`, and then `e`: no more child that Alice can see.
    let next = second.next.clone().unwrap();
    let q = query(
        &format!("parent=host%3Aprod&type=database&limit=1&after={next}"),
        &r.pep,
    );
    let third = r.pep.options(&r.who, &q, None, &Data::new()).unwrap();
    assert!(third.items.is_empty());
    assert_eq!(third.next, None);
}

#[test]
fn p_5_6_the_pep_bounds_the_questions_of_one_request_and_gives_next() {
    let r = rig(|c| c.display_max_questions = 2);
    let mut seen: Vec<String> = Vec::new();
    let mut after: Option<String> = None;
    let mut requests = 0;
    loop {
        let text = match &after {
            None => "parent=host%3Aprod&type=database".to_owned(),
            Some(a) => format!("parent=host%3Aprod&type=database&after={a}"),
        };
        let before = r.server.log().len();
        let answer = r
            .pep
            .options(&r.who, &query(&text, &r.pep), None, &Data::new())
            .unwrap();
        requests += 1;
        assert!(
            r.server.log().len() - before <= 2,
            "at most 2 questions for one request"
        );
        seen.extend(ids(&answer).iter().map(|s| (*s).to_owned()));
        match answer.next {
            Some(next) => after = Some(next),
            None => break,
        }
        assert!(requests < 20);
    }
    assert_eq!(seen, ["test1", "test2"]);
    assert!(
        requests >= 4,
        "8 children with 2 questions each need 4 requests"
    );
}

#[test]
fn p_5_7_an_id_with_a_slash_is_a_child_like_another() {
    let r = rig(|_| {});
    // `a/b` has no grant for Alice, but the route can list the children of `a/b`: the parent path decodes in two steps.
    let q = query("parent=host%3Aprod%2Fdatabase%3Aa%252Fb&type=table", &r.pep);
    assert_eq!(q.parent.nodes()[2].id, "a/b");
    let answer = r.pep.options(&r.who, &q, None, &Data::new()).unwrap();
    assert!(answer.items.is_empty());
}

#[test]
fn p_5_6_a_node_that_does_not_exist_gives_an_answer_with_no_items() {
    let r = rig(|_| {});
    let q = query("parent=host%3Anowhere&type=database", &r.pep);
    let answer = r.pep.options(&r.who, &q, None, &Data::new()).unwrap();
    assert!(answer.items.is_empty());
    assert_eq!(answer.next, None);
}

#[test]
fn p_5_6_the_questions_have_the_type_the_chain_and_match_subtree_without_usage() {
    let t = Scripted::answering(|_| json!({"decision": true}));
    let edge = Edge::new();
    let (pep, _) = pep(t.clone(), &edge, "http://pdp.test", |_| {});
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let q = OptionsQuery::parse("type=host", pep.document()).unwrap();
    let answer = pep.options(&who, &q, None, &Data::new()).unwrap();
    assert_eq!(ids(&answer), ["prod", "staging"]);
    let posts = t.posts();
    assert_eq!(posts.len(), 1);
    let body: Value = posts[0].body.clone().unwrap();
    assert_eq!(body["context"], json!({"match": "subtree"}));
    for item in body["evaluations"].as_array().unwrap() {
        assert_eq!(item["resource"]["type"], "host");
        assert_eq!(
            item["resource"]["properties"]["ancestors"],
            json!([{"type": "service", "id": "datastore"}])
        );
        assert_eq!(item["action"]["name"], "data.read");
    }
    assert!(!posts[0].has_usage());
}

#[test]
fn p_5_6_a_child_that_the_pdp_refuses_for_subtree_is_not_listed() {
    let t = Scripted::answering(|_| json!({"decision": false}));
    let edge = Edge::new();
    let (pep, _) = pep(t, &edge, "http://pdp.test", |_| {});
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let q = OptionsQuery::parse("type=host", pep.document()).unwrap();
    let answer = pep.options(&who, &q, None, &Data::new()).unwrap();
    assert!(answer.items.is_empty());
    assert_eq!(answer.next, None);
}

#[test]
fn p_5_6_a_pdp_that_gives_no_valid_answer_gives_503() {
    for answer in [json!({"decision": "yes"}), json!({"x": 1})] {
        let t = Scripted::answering(move |_| answer.clone());
        let edge = Edge::new();
        let (pep, _) = pep(t, &edge, "http://pdp.test", |_| {});
        let who = pep
            .authenticate([(HEADER, edge.token("alice").as_str())])
            .unwrap();
        let q = OptionsQuery::parse("type=host", pep.document()).unwrap();
        let error = pep.options(&who, &q, None, &Data::new()).unwrap_err();
        assert!(matches!(error, Refusal::Unavailable(_)));
        assert_eq!(error.status(), 503);
    }
}

#[test]
fn p_5_6_an_action_that_the_caller_names_is_the_action_of_the_questions() {
    let t = Scripted::answering(|_| json!({"decision": true}));
    let edge = Edge::new();
    let (pep, _) = pep(t.clone(), &edge, "http://pdp.test", |_| {});
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let q = OptionsQuery::parse("type=host", pep.document()).unwrap();
    pep.options(&who, &q, Some("data.write"), &Data::new())
        .unwrap();
    assert_eq!(
        t.posts()[0].body.clone().unwrap()["evaluations"][0]["action"]["name"],
        "data.write"
    );
}
