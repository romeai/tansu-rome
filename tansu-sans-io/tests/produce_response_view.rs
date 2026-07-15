// Copyright ⓒ 2024-2026 Peter Morgan <peter.james.morgan@gmail.com>
// Licensed under the Apache License, Version 2.0.

use std::cell::Cell;

use bytes::Bytes;
use tansu_sans_io::{
    ApiKey as _, Body, Error, Frame, Header, PRODUCE_RESPONSE_FLEXIBLE_START,
    PRODUCE_RESPONSE_MAX_VERSION, PRODUCE_RESPONSE_MIN_VERSION, ProduceCurrentLeader,
    ProduceNodeEndpointView, ProducePartitionResponseView, ProduceRecordErrorView, ProduceResponse,
    ProduceResponseView, ProduceTopicResponseView, RootMessageMeta, encode_produce_response_view,
    produce_response::{
        BatchIndexAndErrorMessage, LeaderIdAndEpoch, NodeEndpoint, PartitionProduceResponse,
        TopicProduceResponse,
    },
};

#[derive(Clone, Copy)]
struct View<'a> {
    topics: &'a [Topic<'a>],
    throttle_time_ms: i32,
    endpoints: Option<&'a [Endpoint<'a>]>,
}

#[derive(Clone, Copy)]
struct Topic<'a> {
    name: &'a str,
    partitions: &'a [Partition<'a>],
}

#[derive(Clone, Copy)]
struct Partition<'a> {
    index: i32,
    error_code: i16,
    base_offset: i64,
    log_append_time_ms: i64,
    log_start_offset: i64,
    record_errors: &'a [RecordError<'a>],
    error_message: Option<&'a str>,
    current_leader: Option<ProduceCurrentLeader>,
}

#[derive(Clone, Copy)]
struct RecordError<'a> {
    batch_index: i32,
    message: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct Endpoint<'a> {
    node_id: i32,
    host: &'a str,
    port: i32,
    rack: Option<&'a str>,
}

struct ChangingView<'a> {
    inner: View<'a>,
    topic_calls: Cell<usize>,
}

impl ProduceResponseView for ChangingView<'_> {
    type Topic<'a>
        = &'a Topic<'a>
    where
        Self: 'a;
    type Topics<'a>
        = std::vec::IntoIter<&'a Topic<'a>>
    where
        Self: 'a;
    type NodeEndpoint<'a>
        = &'a Endpoint<'a>
    where
        Self: 'a;
    type NodeEndpoints<'a>
        = std::vec::IntoIter<&'a Endpoint<'a>>
    where
        Self: 'a;

    fn topics(&self) -> Self::Topics<'_> {
        let call = self.topic_calls.get();
        self.topic_calls.set(call + 1);
        if call == 0 {
            self.inner.topics.iter().collect::<Vec<_>>().into_iter()
        } else {
            Vec::new().into_iter()
        }
    }

    fn throttle_time_ms(&self) -> i32 {
        self.inner.throttle_time_ms
    }

    fn node_endpoints(&self) -> Option<Self::NodeEndpoints<'_>> {
        None
    }
}

impl ProduceResponseView for View<'_> {
    type Topic<'a>
        = &'a Topic<'a>
    where
        Self: 'a;
    type Topics<'a>
        = std::slice::Iter<'a, Topic<'a>>
    where
        Self: 'a;
    type NodeEndpoint<'a>
        = &'a Endpoint<'a>
    where
        Self: 'a;
    type NodeEndpoints<'a>
        = std::slice::Iter<'a, Endpoint<'a>>
    where
        Self: 'a;

    fn topics(&self) -> Self::Topics<'_> {
        self.topics.iter()
    }
    fn throttle_time_ms(&self) -> i32 {
        self.throttle_time_ms
    }
    fn node_endpoints(&self) -> Option<Self::NodeEndpoints<'_>> {
        self.endpoints.map(<[_]>::iter)
    }
}

impl ProduceTopicResponseView for &Topic<'_> {
    type Partition<'a>
        = &'a Partition<'a>
    where
        Self: 'a;
    type Partitions<'a>
        = std::slice::Iter<'a, Partition<'a>>
    where
        Self: 'a;

    fn name(&self) -> &str {
        self.name
    }
    fn partitions(&self) -> Self::Partitions<'_> {
        self.partitions.iter()
    }
}

impl ProducePartitionResponseView for &Partition<'_> {
    type RecordError<'a>
        = &'a RecordError<'a>
    where
        Self: 'a;
    type RecordErrors<'a>
        = std::slice::Iter<'a, RecordError<'a>>
    where
        Self: 'a;

    fn index(&self) -> i32 {
        self.index
    }
    fn error_code(&self) -> i16 {
        self.error_code
    }
    fn base_offset(&self) -> i64 {
        self.base_offset
    }
    fn log_append_time_ms(&self) -> i64 {
        self.log_append_time_ms
    }
    fn log_start_offset(&self) -> i64 {
        self.log_start_offset
    }
    fn record_errors(&self) -> Self::RecordErrors<'_> {
        self.record_errors.iter()
    }
    fn error_message(&self) -> Option<&str> {
        self.error_message
    }
    fn current_leader(&self) -> Option<ProduceCurrentLeader> {
        self.current_leader
    }
}

impl ProduceRecordErrorView for &RecordError<'_> {
    fn batch_index(&self) -> i32 {
        self.batch_index
    }
    fn message(&self) -> Option<&str> {
        self.message
    }
}

impl ProduceNodeEndpointView for &Endpoint<'_> {
    fn node_id(&self) -> i32 {
        self.node_id
    }
    fn host(&self) -> &str {
        self.host
    }
    fn port(&self) -> i32 {
        self.port
    }
    fn rack(&self) -> Option<&str> {
        self.rack
    }
}

fn pair() -> (ProduceResponse, View<'static>) {
    static RECORD_ERRORS: [RecordError<'static>; 1] = [RecordError {
        batch_index: 4,
        message: Some("bad record"),
    }];
    static PARTITIONS: [Partition<'static>; 1] = [Partition {
        index: 3,
        error_code: 7,
        base_offset: 91,
        log_append_time_ms: 92,
        log_start_offset: 17,
        record_errors: &RECORD_ERRORS,
        error_message: Some("partition failed"),
        current_leader: Some(ProduceCurrentLeader {
            leader_id: 8,
            leader_epoch: 9,
        }),
    }];
    static TOPICS: [Topic<'static>; 1] = [Topic {
        name: "events",
        partitions: &PARTITIONS,
    }];
    static ENDPOINTS: [Endpoint<'static>; 1] = [Endpoint {
        node_id: 8,
        host: "broker.internal",
        port: 9092,
        rack: Some("iad-1"),
    }];

    let owned = ProduceResponse::default()
        .responses(Some(vec![
            TopicProduceResponse::default()
                .name("events".into())
                .partition_responses(Some(vec![
                    PartitionProduceResponse::default()
                        .index(3)
                        .error_code(7)
                        .base_offset(91)
                        .log_append_time_ms(Some(92))
                        .log_start_offset(Some(17))
                        .record_errors(Some(vec![
                            BatchIndexAndErrorMessage::default()
                                .batch_index(4)
                                .batch_index_error_message(Some("bad record".into())),
                        ]))
                        .error_message(Some("partition failed".into()))
                        .current_leader(Some(
                            LeaderIdAndEpoch::default().leader_id(8).leader_epoch(9),
                        )),
                ])),
        ]))
        .throttle_time_ms(Some(13))
        .node_endpoints(Some(vec![
            NodeEndpoint::default()
                .node_id(8)
                .host("broker.internal".into())
                .port(9092)
                .rack(Some("iad-1".into())),
        ]));
    (
        owned,
        View {
            topics: &TOPICS,
            throttle_time_ms: 13,
            endpoints: Some(&ENDPOINTS),
        },
    )
}

fn owned_bytes(response: ProduceResponse, version: i16) -> tansu_sans_io::Result<Bytes> {
    Frame::response(
        Header::Response { correlation_id: 42 },
        Body::ProduceResponse(response),
        ProduceResponse::KEY,
        version,
    )
}

#[test]
fn owned_and_borrowed_views_share_one_writer_for_every_advertised_version() {
    for version in PRODUCE_RESPONSE_MIN_VERSION..=PRODUCE_RESPONSE_MAX_VERSION {
        let (owned, view) = pair();
        let expected = owned_bytes(owned, version).unwrap();
        let actual = encode_produce_response_view(&view, version, 42, usize::MAX).unwrap();
        assert_eq!(expected, actual, "Produce v{version}");

        let decoded =
            Frame::response_from_bytes(&actual[..], ProduceResponse::KEY, version).unwrap();
        assert_eq!(42, decoded.correlation_id().unwrap());
        let decoded = ProduceResponse::try_from(decoded.body).unwrap();
        let topic = &decoded.responses.unwrap()[0];
        assert_eq!("events", topic.name);
        let partition = &topic.partition_responses.as_ref().unwrap()[0];
        assert_eq!(3, partition.index);
        assert_eq!(7, partition.error_code);
        assert_eq!(91, partition.base_offset);
        assert_eq!((version >= 2).then_some(92), partition.log_append_time_ms);
        assert_eq!((version >= 5).then_some(17), partition.log_start_offset);
        assert_eq!(
            (version >= 8).then_some("partition failed"),
            partition.error_message.as_deref()
        );
        assert_eq!(version >= 10, partition.current_leader.is_some());
        assert_eq!(version >= 10, decoded.node_endpoints.is_some());
        assert_eq!((version >= 1).then_some(13), decoded.throttle_time_ms);
    }
}

#[test]
fn advertised_versions_and_flexible_cutover_match_descriptor_exactly() {
    let meta = RootMessageMeta::messages()
        .responses()
        .get(&ProduceResponse::KEY)
        .unwrap();
    assert_eq!(PRODUCE_RESPONSE_MIN_VERSION, meta.version.valid.start);
    assert_eq!(PRODUCE_RESPONSE_MAX_VERSION, meta.version.valid.end);
    for version in PRODUCE_RESPONSE_MIN_VERSION..=PRODUCE_RESPONSE_MAX_VERSION {
        assert_eq!(
            version >= PRODUCE_RESPONSE_FLEXIBLE_START,
            meta.is_flexible(version)
        );
    }
}

#[test]
fn exact_wire_limit_succeeds_and_one_byte_less_fails() {
    let (_, view) = pair();
    let encoded = encode_produce_response_view(&view, 11, 42, usize::MAX).unwrap();
    assert_eq!(
        encoded,
        encode_produce_response_view(&view, 11, 42, encoded.len()).unwrap()
    );
    assert!(matches!(
        encode_produce_response_view(&view, 11, 42, encoded.len() - 1),
        Err(Error::ProduceResponseSizeLimitExceeded { limit, actual })
            if limit == encoded.len() - 1 && actual == encoded.len()
    ));
}

#[test]
fn versions_outside_the_descriptor_are_exact_errors() {
    let (_, view) = pair();
    for version in [
        PRODUCE_RESPONSE_MIN_VERSION - 1,
        PRODUCE_RESPONSE_MAX_VERSION + 1,
    ] {
        assert!(matches!(
            encode_produce_response_view(&view, version, 42, usize::MAX),
            Err(Error::UnsupportedProduceResponseVersion {
                version: actual,
                minimum: PRODUCE_RESPONSE_MIN_VERSION,
                maximum: PRODUCE_RESPONSE_MAX_VERSION,
            }) if actual == version
        ));
    }
}

#[test]
fn a_non_replayable_view_fails_instead_of_reallocating_or_emitting_partial_bytes() {
    let (_, inner) = pair();
    let view = ChangingView {
        inner,
        topic_calls: Cell::new(0),
    };
    assert!(matches!(
        encode_produce_response_view(&view, 0, 42, usize::MAX),
        Err(Error::ProduceResponseViewChanged { expected, actual }) if actual < expected
    ));
}
