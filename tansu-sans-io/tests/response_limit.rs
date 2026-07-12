// Copyright ⓒ 2024-2025 Peter Morgan <peter.james.morgan@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tansu_sans_io::{
    ApiKey as _, ApiVersionsResponse, Error, ErrorCode, Frame, Header,
    api_versions_response::ApiVersion,
};

fn response() -> ApiVersionsResponse {
    ApiVersionsResponse::default()
        .error_code(ErrorCode::None.into())
        .api_keys(Some(vec![
            ApiVersion::default()
                .api_key(18)
                .min_version(0)
                .max_version(4),
        ]))
        .throttle_time_ms(Some(0))
        .supported_features(Some(Vec::new()))
        .finalized_features_epoch(Some(-1))
        .finalized_features(Some(Vec::new()))
        .zk_migration_ready(Some(false))
}

#[test]
fn response_capacity_is_rejected_before_the_encoder_is_constructed() {
    let error = Frame::response_with_limit(
        Header::Response { correlation_id: 7 },
        response().into(),
        ApiVersionsResponse::KEY,
        4,
        4,
    )
    .unwrap_err();
    let Error::ResponseWireLimitExceeded { required, limit } = error else {
        panic!("unexpected response-limit error: {error:?}");
    };
    assert_eq!(4, limit);
    assert!(required > limit);

    let encoded = Frame::response_with_limit(
        Header::Response { correlation_id: 7 },
        response().into(),
        ApiVersionsResponse::KEY,
        4,
        required,
    )
    .unwrap();
    assert!(encoded.len() <= required);

    assert!(matches!(
        Frame::response_with_limit(
            Header::Response { correlation_id: 7 },
            response().into(),
            ApiVersionsResponse::KEY,
            4,
            required - 1,
        ),
        Err(Error::ResponseWireLimitExceeded {
            required: actual,
            limit,
        }) if actual == required && limit == required - 1
    ));
}
