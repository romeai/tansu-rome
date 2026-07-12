// Copyright ⓒ 2024-2025 Peter Morgan <peter.james.morgan@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rama::{Context, Service};
use tansu_sans_io::{
    AddPartitionsToTxnRequest, AddPartitionsToTxnResponse, ApiKey, ErrorCode,
    add_partitions_to_txn_response::{
        AddPartitionsToTxnPartitionResult, AddPartitionsToTxnResult, AddPartitionsToTxnTopicResult,
    },
};
use tracing::instrument;

use crate::{
    Error, Result, Storage, TxnAddPartitionsRequest, TxnAddPartitionsResponse,
    service::ApiErrorResponseExt as _,
};

fn failed_response(request: &TxnAddPartitionsRequest, code: ErrorCode) -> TxnAddPartitionsResponse {
    let topics =
        |topics: &[tansu_sans_io::add_partitions_to_txn_request::AddPartitionsToTxnTopic]| {
            topics
                .iter()
                .map(|topic| {
                    AddPartitionsToTxnTopicResult::default()
                        .name(topic.name.clone())
                        .results_by_partition(Some(
                            topic
                                .partitions
                                .as_deref()
                                .unwrap_or_default()
                                .iter()
                                .map(|partition| {
                                    AddPartitionsToTxnPartitionResult::default()
                                        .partition_index(*partition)
                                        .partition_error_code(code.into())
                                })
                                .collect(),
                        ))
                })
                .collect()
        };
    match request {
        TxnAddPartitionsRequest::VersionZeroToThree {
            topics: requested, ..
        } => TxnAddPartitionsResponse::VersionZeroToThree(topics(requested)),
        TxnAddPartitionsRequest::VersionFourPlus { transactions } => {
            TxnAddPartitionsResponse::VersionFourPlus(
                transactions
                    .iter()
                    .map(|transaction| {
                        AddPartitionsToTxnResult::default()
                            .transactional_id(transaction.transactional_id.clone())
                            .topic_results(Some(topics(
                                transaction.topics.as_deref().unwrap_or_default(),
                            )))
                    })
                    .collect(),
            )
        }
    }
}

/// A [`Service`] using [`Storage`] as [`Context`] taking [`AddPartitionsToTxnRequest`] returning [`AddPartitionsToTxnResponse`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AddPartitionService;

impl ApiKey for AddPartitionService {
    const KEY: i16 = AddPartitionsToTxnRequest::KEY;
}

impl<G> Service<G, AddPartitionsToTxnRequest> for AddPartitionService
where
    G: Storage,
{
    type Response = AddPartitionsToTxnResponse;
    type Error = Error;

    #[instrument(skip(ctx, req))]
    async fn serve(
        &self,
        ctx: Context<G>,
        req: AddPartitionsToTxnRequest,
    ) -> Result<Self::Response, Self::Error> {
        let req = TxnAddPartitionsRequest::try_from(req)?;

        let response = ctx
            .state()
            .txn_add_partitions(req.clone())
            .await
            .map_api_response(|response| response, |code| failed_response(&req, code))?;
        match response {
            TxnAddPartitionsResponse::VersionZeroToThree(results_by_topic_v_3_and_below) => {
                Ok(AddPartitionsToTxnResponse::default()
                    .throttle_time_ms(0)
                    .error_code(Some(ErrorCode::None.into()))
                    .results_by_transaction(Some([].into()))
                    .results_by_topic_v_3_and_below(Some(results_by_topic_v_3_and_below)))
            }

            TxnAddPartitionsResponse::VersionFourPlus(results_by_transaction) => {
                Ok(AddPartitionsToTxnResponse::default()
                    .throttle_time_ms(0)
                    .error_code(Some(ErrorCode::None.into()))
                    .results_by_transaction(Some(results_by_transaction))
                    .results_by_topic_v_3_and_below(Some([].into())))
            }
        }
    }
}
