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
    ApiKey, DeleteRecordsRequest, DeleteRecordsResponse, ErrorCode,
    delete_records_response::{DeleteRecordsPartitionResult, DeleteRecordsTopicResult},
};
use tracing::instrument;

use crate::{Error, Result, Storage, service::ApiErrorResponseExt as _};

fn failed_topics(
    topics: &[tansu_sans_io::delete_records_request::DeleteRecordsTopic],
    code: ErrorCode,
) -> Vec<DeleteRecordsTopicResult> {
    topics
        .iter()
        .map(|topic| {
            DeleteRecordsTopicResult::default()
                .name(topic.name.clone())
                .partitions(Some(
                    topic
                        .partitions
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|partition| {
                            DeleteRecordsPartitionResult::default()
                                .partition_index(partition.partition_index)
                                .low_watermark(-1)
                                .error_code(code.into())
                        })
                        .collect(),
                ))
        })
        .collect()
}

/// A [`Service`] using [`Storage`] as [`Context`] taking [`DeleteRecordsRequest`] returning [`DeleteRecordsResponse`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeleteRecordsService;

impl ApiKey for DeleteRecordsService {
    const KEY: i16 = DeleteRecordsRequest::KEY;
}

impl<G> Service<G, DeleteRecordsRequest> for DeleteRecordsService
where
    G: Storage,
{
    type Response = DeleteRecordsResponse;
    type Error = Error;

    #[instrument(skip(ctx, req))]
    async fn serve(
        &self,
        ctx: Context<G>,
        req: DeleteRecordsRequest,
    ) -> Result<Self::Response, Self::Error> {
        let requested = req.topics.unwrap_or_default();
        ctx.state()
            .delete_records(&requested)
            .await
            .map_api_response(|topics| topics, |code| failed_topics(&requested, code))
            .map(Some)
            .map(|topics| {
                DeleteRecordsResponse::default()
                    .throttle_time_ms(0)
                    .topics(topics)
            })
    }
}
