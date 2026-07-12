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
    ApiKey, CreateAclsRequest, CreateAclsResponse, ErrorCode,
    create_acls_response::AclCreationResult,
};

use crate::{Error, Storage};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CreateAclsService;

impl ApiKey for CreateAclsService {
    const KEY: i16 = CreateAclsRequest::KEY;
}

impl<G> Service<G, CreateAclsRequest> for CreateAclsService
where
    G: Storage,
{
    type Response = CreateAclsResponse;
    type Error = Error;

    async fn serve(
        &self,
        _ctx: Context<G>,
        req: CreateAclsRequest,
    ) -> Result<Self::Response, Self::Error> {
        // Storage has no ACL mutation contract. Reporting success would imply
        // authorization state changed even though no backend can retain it.
        let error_code = ErrorCode::SecurityDisabled;
        Ok(CreateAclsResponse::default()
            .throttle_time_ms(0)
            .results(Some(
                req.creations
                    .unwrap_or_default()
                    .into_iter()
                    .map(|_| {
                        AclCreationResult::default()
                            .error_code(error_code.into())
                            .error_message(Some(error_code.to_string()))
                    })
                    .collect(),
            )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_acl_mutations_preserve_request_cardinality() {
        let request = CreateAclsRequest::default()
            .creations(Some(vec![Default::default(), Default::default()]));
        let error_code = ErrorCode::SecurityDisabled;
        let response = CreateAclsResponse::default().results(Some(
            request
                .creations
                .unwrap()
                .into_iter()
                .map(|_| AclCreationResult::default().error_code(error_code.into()))
                .collect(),
        ));
        assert_eq!(2, response.results.unwrap().len());
    }
}
